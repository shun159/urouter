/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 * This file contains parsing functions that are used in the packetXX XDP
 * programs. The functions are marked as __always_inline, and fully defined in
 * this header file to be included in the BPF program.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type
 * field. All return values are in host byte order.
 *
 * The versions of the functions included here are slightly expanded versions
 * of the functions in the packet01 lesson. For instance, the Ethernet header
 * parsing has support for parsing VLAN tags.
 */

#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN		*/

#include "vmlinux.h"
/*
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>


*/
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
#define memset(buf, ch, n) __builtin_memset((buf), (ch), (n))
#endif

#define VR_MAC_CMP(dst, src)                               \
	((((uint16_t *)dst)[0] == ((uint16_t *)src)[0]) && \
	 (((uint16_t *)dst)[1] == ((uint16_t *)src)[1]) && \
	 (((uint16_t *)dst)[2] == ((uint16_t *)src)[2]))

#define IS_MAC_ZERO(dst)                                               \
	((((uint16_t *)dst)[0] == 0) && (((uint16_t *)dst)[1] == 0) && \
	 (((uint16_t *)dst)[2] == 0))

#define IS_MAC_BCAST(dst)                    \
	((((uint16_t *)dst)[0] == 0xffff) && \
	 (((uint16_t *)dst)[1] == 0xffff) && (((uint16_t *)dst)[2] == 0xffff))

#define IS_MAC_BMCAST(dst) (((uint8_t *)dst)[0] & 0x1)

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

 */
/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common {
	u8 type;
	u8 code;
	s16 cksum;
};

/*
 *	This structure defines an ethernet arp header.
 */
struct arp_hdr {
	__be16 ar_hrd; /* format of hardware address	*/
	__be16 ar_pro; /* format of protocol address	*/
	unsigned char ar_hln; /* length of hardware address	*/
	unsigned char ar_pln; /* length of protocol address	*/
	__be16 ar_op; /* ARP opcode (command)		*/

	unsigned char ar_sha[ETH_ALEN]; /* sender hardware address	*/
	unsigned char ar_sip[4]; /* sender IP address		*/
	unsigned char ar_tha[ETH_ALEN]; /* target hardware address	*/
	unsigned char ar_tip[4]; /* target IP address		*/
} __attribute__((packed));

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */
/* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
					     void *data_end,
					     struct ethhdr **ethhdr,
					     struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
   * is after data_end.
   */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

/* Use loop unrolling to avoid the verifier restriction on loops;
 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
 */
#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
					struct ethhdr **ethhdr)
{
	/* Expect compiler removes the code that collects VLAN ids */
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

static __always_inline int parse_arphdr(struct hdr_cursor *nh, void *data_end,
					struct arp_hdr **arp)
{
	struct arp_hdr *arph = nh->pos;

	// Pointer-arithmetic bounds check; pointer+1 points to after end of
	// thing being pointed to.
	if (arph + 1 > data_end)
		return -1;

	nh->pos = arph + 1;
	*arp = arph;

	return arph->ar_pro;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh, void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
   * thing being pointed to. We will be using this style in the remainder
   * of the tutorial.
   */
	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if (hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh, void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	nh->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh, void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;

	if (icmph + 1 > data_end)
		return -1;

	nh->pos = icmph + 1;
	*icmphdr = icmph;

	return icmph->type;
}

static __always_inline int parse_icmphdr_common(struct hdr_cursor *nh,
						void *data_end,
						struct icmphdr_common **icmphdr)
{
	struct icmphdr_common *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos = h + 1;
	*icmphdr = h;

	return h->type;
}

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh, void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh, void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if (len < sizeof(*h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return len;
}

static __always_inline uint16_t csum_fold_helper(uint32_t csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

#endif /* __PARSING_HELPERS_H */
