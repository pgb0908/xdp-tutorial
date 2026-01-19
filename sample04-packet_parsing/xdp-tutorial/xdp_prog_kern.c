/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "./common/xdp_stats_kern_user.h"
#include "./common/xdp_stats_kern.h"
#include <linux/ip.h>   // IPv4 헤더 (struct iphdr)
#include <linux/icmp.h> // ICMPv4 헤더 (struct icmphdr)

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
       return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}

/* IPv4 헤더 파싱 */
static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	/* 1. 기본 구조체 크기 검사 (20 bytes) */
	if (iph + 1 > data_end)
		return -1;

	/* 2. 실제 헤더 크기 계산 (IHL field * 4) */
	hdrsize = iph->ihl * 4;

	/* 3. 무결성 검사: 계산된 크기가 기본 크기보다 작으면 에러 */
	if (hdrsize < sizeof(*iph))
		return -1;

	/* 4. 가변 길이 경계 검사: 실제 크기만큼 메모리에 있는지 확인 */
	if ((void *)iph + hdrsize > data_end)
		return -1;

	/* 커서 이동 및 포인터 저장 */
	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol; /* 다음 프로토콜 (TCP/UDP/ICMP 등) 반환 */
}

/* Assignment 5: ICMPv4 헤더 파싱 */
static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;

	/* 1. 경계 검사 */
	if (icmph + 1 > data_end)
		return -1;

	/* 2. IPv4 Ping Request(Type 8) 확인 */
	/* 참고: ICMPv6는 128번이지만, IPv4 ICMP는 8번입니다. */
	if (icmph->type != ICMP_ECHO)
		return -1;

	nh->pos = icmph + 1;
	*icmphdr = icmph;

	/* 시퀀스 번호 반환 (Network Byte Order -> Host Byte Order) */
	return bpf_ntohs(icmph->un.echo.sequence);
}



/*  패킷 파싱을 위한 헬퍼 함수
	기능: 각 헬퍼 함수는 패킷 헤더를 파싱하며, 안전을 위해 메모리 범위(Bounds) 검사를 수행합니다.
	반환값:
		성공 시: 포함된 **콘텐츠의 타입(Type)**을 반환합니다.
		실패 시: -1을 반환합니다.
	'콘텐츠 타입'의 의미:
		Ethernet/IP: 다음 계층의 프로토콜 번호 (예: 이더넷의 h_proto, IPv6의 nexthdr).
		ICMP: ICMP 메시지의 type 필드 값.
	데이터 형식: 모든 반환 값은 네트워크 바이트 오더(Big Endian) 형태입니다.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* 1. 이더넷 헤더 크기만큼 경계 검사 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
    
    /* 2. VLAN 태그 파싱 루프 */
    /* VLAN이 중첩될 수 있으므로 루프로 처리 */
    #pragma unroll
    for (int i = 0; i < 2; i++) {  // 보통 VLAN은 최대 2개까지만 겹쳐서 사용
        if (proto_is_vlan(eth->h_proto)) {
            struct vlan_hdr *vhdr = nh->pos;
            
            /* VLAN 헤더 경계 검사 (4바이트) */
            if (nh->pos + sizeof(struct vlan_hdr) > data_end)
                return -1;
            
            /* 다음 프로토콜 정보 가져오기 (IPv4/IPv6 등) */
            eth->h_proto = vhdr->h_vlan_encapsulated_proto;
            
            /* 커서 이동: VLAN 태그만큼 건너뛰기 */
            nh->pos += sizeof(struct vlan_hdr);
        } else {
            break; /* VLAN이 아니면 루프 종료 */
        }
    }

	return eth->h_proto; /* 최종 프로토콜 리턴 */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
       struct ipv6hdr *ip6h = nh->pos;

       if (ip6h + 1 > data_end)
               return -1;
       nh->pos = ip6h + 1;
       *ip6hdr = ip6h;
       return ip6h->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
       struct icmp6hdr *icmp6h = nh->pos;

       if (icmp6h + 1 > data_end)
               return -1;


	// [중요] Echo Request (Ping 요청)가 아니면 -1 리턴 (또는 다른 값)
	// 128: Echo Request, 129: Echo Reply
	if (icmp6h->icmp6_type != ICMPV6_ECHO_REQUEST) 
        	return -1;

	nh->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	// Echo Request일 때만 시퀀스 번호가 의미가 있음
       return bpf_ntohs(icmp6h->icmp6_sequence);
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	// IPv6용 포인터
	struct ipv6hdr *ipv6;
	struct icmp6hdr *icmp6;

	// IPv4용 포인터
	struct iphdr *iph;
	struct icmphdr *icmp;
	
	int icmp_seq = -1; // 초기값 설정
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* 1. 이더넷 파싱 (VLAN 포함) */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	/* 2. 프로토콜 분기 처리 */
	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		// [기존 IPv6 로직]
		nh_type = parse_ip6hdr(&nh, data_end, &ipv6);
		
		if (nh_type != IPPROTO_ICMPV6) goto out;
		icmp_seq = parse_icmp6hdr(&nh, data_end, &icmp6);
		
	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		// [새로운 IPv4 로직]
		nh_type = parse_ip4hdr(&nh, data_end, &iph);

		// 프로토콜이 ICMP(1)인지 확인
		if (nh_type != IPPROTO_ICMP) goto out;
		icmp_seq = parse_icmp4hdr(&nh, data_end, &icmp);

	} else {
		// IPv4도 IPv6도 아니면 패스
		goto out;
	}

	/* 3. 공통 필터링 로직 (IPv4/IPv6 공통) */
	// 핑이 아니거나(-1), 홀수 시퀀스면 통과
	if (icmp_seq == -1 || icmp_seq % 2 == 1)
		goto out;

	// 짝수 시퀀스 핑만 DROP
	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
