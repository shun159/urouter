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

#include <linux/types.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>
#include "urouter_helpers.bpf.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

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
    __uint(key_size, ETH_ALEN);
} bridge_table SEC(".maps");

// helper functions

static __always_inline
uint32_t update_stats(struct xdp_md *ctx, __u32 action) {
	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&stats, &action);
	if (!rec)
		return XDP_ABORTED;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);

	return action;
}

//
// eBPF functions
//

SEC("xdp_redirect")
int xdp_redirect_fn(struct xdp_md *ctx) {
    return XDP_REDIRECT;
}

SEC("xdp_router")
int xdp_router_fn(struct xdp_md *ctx) {
    return XDP_PASS;
}

SEC("xdp_pass")
int xdp_pass_fn(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

