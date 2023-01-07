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
	unsigned short vlan_id;
	uint32_t domain_id;
} __attribute__((packed));

/* config entry per interface */
struct vif_entry {
	uint32_t domain_id;
} __attribute__((packed));

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

/*
 * Map definitions
 *  - tx_ports: used for redirect packet
 *  - domain: used for define broadcast domain.
 *  - virtual_interfaces(vif): interface configuration
 *  - bridge_table: shared FIB table backed by LRU hash table.
 *
 *        +----------------------------------------+
 *        |                                        |
 *        | +-----------+                          |
 * vif1 <-----          |  logical L2 switch       | 
 *        | |  domain1  |                          |
 * vif2 <-----          | <--+       +-----------+ |
 *        | +-----------+    | r/w   | Shared    | |
 *        |                  +-----> | FIB table | |
 *        | +-----------+    |       |           | |
 * vif3 <-----          | <--+       +-----------+ |
 *        | |  domain2  |                          |
 * vif4 <-----          |                          |
 *        | +-----------+                          |
 *        |                                        |
 *        +----------------------------------------+
 */

struct domain_devmap {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 256);
	__type(key, uint32_t);
	__type(value, uint32_t);
} tx_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 1000);
	__type(key, uint32_t);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__array(values, struct domain_devmap);
} domain_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, struct vif_entry);
	__uint(max_entries, 256);
} urouter_vif SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct mac_entry);
	__type(value, uint32_t);
	__uint(max_entries, 1000);
} bridge_table SEC(".maps");

//
// eBPF functions
//
static __always_inline int bridge_input(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct collect_vlans vlans;
	struct mac_entry entry = {};
	uint32_t ingress_ifindex;

	nh.pos = data;
	int eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);

	if (eth_type < 0)
		return XDP_ABORTED;

	memcpy(&entry.address, eth->h_source, ETH_ALEN);
	memcpy(&ingress_ifindex, &ctx->ingress_ifindex, sizeof(uint32_t));

	// MAC learning
	bpf_map_update_elem(&bridge_table, &entry, &ingress_ifindex, 0);

	return 0;
}

static __always_inline int vm_rx(struct xdp_md *ctx)
{
	uint32_t in_port = ctx->ingress_ifindex;
	struct vif_entry *vif = bpf_map_lookup_elem(&urouter_vif, &in_port);
	if (!vif)
		return -1;
	return 0;
}

SEC("xdp_redirect")
int xdp_redirect_fn(struct xdp_md *ctx)
{
	return XDP_REDIRECT;
}

SEC("xdp_router")
int xdp_router_fn(struct xdp_md *ctx)
{
	bridge_input(ctx);
	return XDP_PASS;
}

SEC("xdp_pass")
int xdp_pass_fn(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
