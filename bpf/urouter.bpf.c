/* Copyright (C) 2022-present, Eishun Kondoh <dreamdiagnosis@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU GPL as published by
 * the FSF; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "urouter_helpers.bpf.h"

char _license[] SEC("license") = "GPL";

struct bpf_ct_opts___local {
	s32 netns_id;
	s32 error;
	u8 l4proto;
	u8 reserved[3];
} __attribute__((preserve_access_index));

struct nf_conn___init *bpf_xdp_ct_alloc(struct xdp_md *,
					struct bpf_sock_tuple *, u32,
					struct bpf_ct_opts___local *,
					u32) __ksym;

struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *, struct bpf_sock_tuple *, u32,
				  struct bpf_ct_opts___local *, u32) __ksym;
struct nf_conn *bpf_skb_ct_alloc(struct __sk_buff *, struct bpf_sock_tuple *,
				 u32, struct bpf_ct_opts___local *, u32) __ksym;
struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *,
				  u32, struct bpf_ct_opts___local *,
				  u32) __ksym;
struct nf_conn *bpf_ct_insert_entry(struct nf_conn___init *) __ksym;
void bpf_ct_release(struct nf_conn *) __ksym;
void bpf_ct_set_timeout(struct nf_conn *, u32) __ksym;
int bpf_ct_change_timeout(struct nf_conn *, u32) __ksym;
int bpf_ct_set_status(struct nf_conn *, u32) __ksym;
int bpf_ct_change_status(struct nf_conn *, u32) __ksym;
int bpf_ct_set_nat_info(struct nf_conn *, union nf_inet_addr *, int port,
			enum nf_nat_manip_type) __ksym;

/* This is the data record stored in the map */
struct datarec {
	uint64_t rx_packets;
	uint64_t rx_bytes;
};

/* This is the Bridge entry stored in the map*/
struct mac_entry {
	unsigned char address[ETH_ALEN]; /* destination eth addr */
} __attribute__((packed));

/* virtual interface configuration entry in the map */
enum vif_type {
	UR_VIF_DOWNLINK,
	UR_VIF_UPLINK,
	UR_VIF_IRB,
};

struct vif_entry {
	uint32_t vif_type;
	unsigned char mac[ETH_ALEN];
	uint32_t ip4;
	uint64_t ip6u;
	uint64_t ip6l;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, uint32_t);
	__type(value, enum vif_type);
	__uint(max_entries, 256);
} tx_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct mac_entry);
	__type(value, uint32_t);
	__uint(max_entries, 1000);
} bridge_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, struct vif_entry);
	__uint(max_entries, 256);
} vif_table SEC(".maps");

// ur_trap_rb use as an interface for traps unhandled packets to userspace program.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ur_trap_rb SEC(".maps");

//
// eBPF functions
//
static __always_inline int bridge_input(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct mac_entry entry = {};

	uint32_t index;
	uint32_t ingress_ifindex;
	uint64_t redirect_flags = 0;

	nh.pos = data;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);

	if (eth_type < 0)
		return XDP_ABORTED;

	memcpy(&entry.address, eth->h_source, ETH_ALEN);
	memcpy(&ingress_ifindex, &ctx->ingress_ifindex, sizeof(uint32_t));

	// MAC learning
	bpf_map_update_elem(&bridge_table, &entry, &ingress_ifindex, 0);

	// Forwarding
	uint32_t *tmp_index =
		(uint32_t *)bpf_map_lookup_elem(&bridge_table, &eth->h_dest);
	if ((!tmp_index) || (IS_MAC_BMCAST(eth->h_dest))) {
		redirect_flags = BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS;
		index = 0;
	} else {
		memcpy(&index, tmp_index, sizeof(uint32_t));
	}

	int ret = bpf_redirect_map(&tx_ports, index, redirect_flags);
	return ret;
}

static __always_inline int vm_rx(struct xdp_md *ctx)
{
	struct vif_entry *vif;
	uint32_t ingress_ifindex;

	struct nf_conn *ct_ins;
	struct bpf_ct_opts___local opts_def = {
		.l4proto = IPPROTO_TCP, .netns_id = -1,
	};
	struct bpf_sock_tuple bpf_tuple;

	bpf_tuple.ipv4.saddr = 0x01010101; /* src IP */
	bpf_tuple.ipv4.daddr = 0x02020202; /* dst IP */
	bpf_tuple.ipv4.sport = bpf_get_prandom_u32(); /* src port */
	bpf_tuple.ipv4.dport = bpf_get_prandom_u32(); /* dst port */

	struct nf_conn___init *ct;
	ct = bpf_xdp_ct_alloc(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4),
			      &opts_def, sizeof(opts_def));
	if (!ct) {
		bpf_printk("aborted! #1");
		return XDP_ABORTED;
	}

	ct_ins = bpf_ct_insert_entry(ct);
	if (!ct_ins) {
		bpf_printk("aborted! #2");
		return XDP_ABORTED;
	}

	bpf_ct_release(ct_ins);

	memcpy(&ingress_ifindex, &ctx->ingress_ifindex, sizeof(uint32_t));

	vif = (struct vif_entry *)bpf_map_lookup_elem(&vif_table,
						      &ingress_ifindex);
	if (!vif)
		return -1;

	bpf_printk("vif_type: %d\n", vif->vif_type);
	return XDP_PASS;
}

SEC("xdp_router")
int xdp_router_fn(struct xdp_md *ctx)
{
	int ret;

	ret = vm_rx(ctx);
	if (ret < 0)
		return XDP_ABORTED;

	ret = bridge_input(ctx);
	return ret;
}

SEC("xdp_redirect")
int xdp_redirect_fn(struct xdp_md *ctx)
{
	return XDP_PASS;
}
