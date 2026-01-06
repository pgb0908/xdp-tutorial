#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h" // ★ 여기에 공통 헤더 포함


// 설정을 저장할 BPF 맵 (Array 타입, 인덱스 0번 하나만 사용)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lb_config);
} lb_map SEC(".maps");

// IP 체크섬 계산을 위한 간단한 헬퍼 함수
static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

// 2. 메인 XDP 프로그램
SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // 1. 기본 패킷 파싱 (Ethernet)
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // IPv4가 아니면 통과
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // TCP가 아니면 통과 (블로그 예제 조건)
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 2. 설정(백엔드 서버 정보) 가져오기
    __u32 key = 0;
    struct lb_config *config = bpf_map_lookup_elem(&lb_map, &key);
    if (!config) {
        return XDP_PASS; // 설정이 없으면 그냥 통과
    }

    // 3. 헤더 공간 확보 (IPIP 캡슐화를 위해 IP 헤더 크기만큼 공간 늘리기)
    // bpf_xdp_adjust_head는 음수 값을 주면 헤더 공간이 늘어납니다 (앞으로 확장).
    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr)))
        return XDP_DROP; // 공간 확보 실패 시 드랍

    // adjust_head 이후 포인터가 변경되므로 다시 초기화해야 함 (필수!)
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // 포인터 재설정
    struct ethhdr *new_eth = data;
    struct iphdr *outer_iph = (void *)(new_eth + 1); // 새로 추가된 IP 헤더 위치
    struct iphdr *inner_iph = (void *)(outer_iph + 1); // 원본 IP 헤더 위치

    // 경계 검사 (Verifier 통과를 위해 다시 확인)
    if ((void *)(inner_iph + 1) > data_end)
        return XDP_DROP;

    // 4. 이더넷 헤더 이동 및 수정
    // 원본 이더넷 헤더는 adjust_head로 인해 깨졌거나 위치가 안 맞으므로
    // 새로운 이더넷 헤더를 앞에 작성합니다.
    // (메모리 복사 대신 직접 값을 설정합니다)
    __builtin_memcpy(new_eth->h_dest, config->dst_mac, 6);   // 목적지: 백엔드 서버 MAC
    __builtin_memcpy(new_eth->h_source, config->src_mac, 6); // 출발지: LB MAC
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    // 5. IPIP (Outer) IP 헤더 작성
    outer_iph->version = 4;
    outer_iph->ihl = 5;
    outer_iph->tos = inner_iph->tos; // 원본 TOS 유지
    // 전체 길이 = 원본 패킷 길이 + 새 IP 헤더 크기
    outer_iph->tot_len = bpf_htons(bpf_ntohs(inner_iph->tot_len) + sizeof(struct iphdr));
    outer_iph->id = 0; // Fragmentation 없을 경우 0 가능
    outer_iph->frag_off = 0;
    outer_iph->ttl = 64;
    outer_iph->protocol = IPPROTO_IPIP; // ★ 핵심: 프로토콜 4번 (IPIP)
    outer_iph->saddr = config->lb_vip;       // 출발지: LB VIP
    outer_iph->daddr = config->real_server_ip; // 목적지: 백엔드 서버 IP
    
    // 체크섬 계산
    outer_iph->check = iph_csum(outer_iph);

    // 6. 패킷 전송 (XDP_TX)
    // 들어온 인터페이스로 다시 내보냅니다.
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";