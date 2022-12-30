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
} __attribute__((packed));

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
  __type(key, uint32_t);
  __type(value, struct bpf_devmap_val);
  __uint(max_entries, 256);
} tx_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, uint32_t);
  __type(value, struct datarec);
  __uint(max_entries, XDP_ACTION_MAX);
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct mac_entry);
  __type(value, uint32_t);
  __uint(max_entries, 1000);
} bridge_table SEC(".maps");

//
// eBPF functions
//
static __always_inline int bridge_input(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct hdr_cursor nh;
  struct ethhdr *eth;
  struct collect_vlans vlans;
  struct mac_entry entry = {};

  int eth_type;
  uint32_t ingress_ifindex;

  nh.pos = data;
  eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);

  if (eth_type < 0) return XDP_ABORTED;
  memcpy(&entry.address, eth->h_source, ETH_ALEN);
  memcpy(&ingress_ifindex, &ctx->ingress_ifindex, sizeof(uint32_t));

  // MAC learning
  bpf_map_update_elem(&bridge_table, &entry, &ingress_ifindex, 0);

  return 0;
}

SEC("xdp_redirect")
int xdp_redirect_fn(struct xdp_md *ctx) { return XDP_REDIRECT; }

SEC("xdp_router")
int xdp_router_fn(struct xdp_md *ctx) {
  bridge_input(ctx);
  return XDP_PASS;
}

SEC("xdp_pass")
int xdp_pass_fn(struct xdp_md *ctx) { return XDP_PASS; }

char _license[] SEC("license") = "GPL";
