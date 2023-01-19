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

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "urouter_helpers.bpf.h"

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

    memcpy(&ingress_ifindex,&ctx->ingress_ifindex, sizeof(uint32_t));

    vif = (struct vif_entry *)bpf_map_lookup_elem(&vif_table, &ingress_ifindex);
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
    if (ret == -1)
        return XDP_ABORTED;

	ret = bridge_input(ctx);
	return ret;
}

char _license[] SEC("license") = "GPL";
