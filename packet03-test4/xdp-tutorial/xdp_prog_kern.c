/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "./common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "./common/xdp_stats_kern_user.h"
#include "./common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 256);
	//__uint(pinning, LIBBPF_PIN_BY_NAME);
} tx_port SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,  unsigned char[ETH_ALEN]);
	__type(value, unsigned char[ETH_ALEN]);
	__uint(max_entries, 1);
	//__uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_params SEC(".maps");

static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	/* Assignment 1: swap source and destination addresses in the eth.
	 * For simplicity you can use the memcpy macro defined above */
       unsigned char   tmp[ETH_ALEN];
       memcpy(tmp, eth->h_dest, sizeof(eth->h_dest));
       memcpy(eth->h_dest, eth->h_source, sizeof(eth->h_dest));
       memcpy(eth->h_source, tmp, sizeof(eth->h_dest));
}

static __always_inline void swap_src_dst_ipv6(struct ipv6hdr *ipv6)
{
	/* Assignment 1: swap source and destination addresses in the iphv6dr */
       struct in6_addr tmp;
       memcpy(&tmp, &ipv6->daddr, sizeof(struct in6_addr));
       memcpy(&ipv6->daddr, &ipv6->saddr, sizeof(struct in6_addr));
       memcpy(&ipv6->saddr, &tmp, sizeof(struct in6_addr));
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	/* Assignment 1: swap source and destination addresses in the iphdr */
       __be32 tmp;
       memcpy(&tmp, &iphdr->daddr, sizeof(iphdr->daddr));
       memcpy(&iphdr->daddr, &iphdr->saddr, sizeof(iphdr->daddr));
       memcpy(&iphdr->saddr, &tmp, sizeof(iphdr->daddr));	
}


/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	/* Assignment 4: see samples/bpf/xdp_fwd_kern.c from the kernel */
	
	__u32 check = (__u32)iph->check;
        check += (__u32)bpf_htons(0x0100);
        iph->check = (__u16)(check + (check >= 0xFFFF));
	
	return --iph->ttl;
}

/* Assignment 4: Complete this router program */
SEC("xdp")
int xdp_router_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	int action = XDP_PASS;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (iph->ttl <= 1)
			goto out;

		/* Assignment 4: fill the fib_params structure for the AF_INET case */
               fib_params.family = AF_INET;
               fib_params.l4_protocol  = iph->protocol;
               fib_params.ipv4_src = iph->saddr;
               fib_params.ipv4_dst = iph->daddr;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		/* These pointers can be used to assign structures instead of executing memcpy: */
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (ip6h->hop_limit <= 1)
			goto out;

		/* Assignment 4: fill the fib_params structure for the AF_INET6 case */
               fib_params.family = AF_INET6;
               fib_params.l4_protocol  = ip6h->nexthdr;
               *src = ip6h->saddr;
               *dst = ip6h->daddr;
	} else {
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		/* Assignment 4: fill in the eth destination and source
		 * addresses and call the bpf_redirect function */
		/* memcpy(eth->h_dest, ???, ETH_ALEN); */
		/* memcpy(eth->h_source, ???, ETH_ALEN); */
		/* action = bpf_redirect(???, 0); */
                memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
                memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
                action = bpf_redirect(fib_params.ifindex, 0);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		/* PASS */
		break;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
