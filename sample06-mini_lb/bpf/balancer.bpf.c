// balancer.bpf.c
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 데이터 구조 정의 */
struct vip_definition {
    __u32 vip;   // Virtual IP
    __u32 port;  // Port
};

struct real_server {
    __u32 ip;             // Backend IP
    unsigned char mac[6]; // Backend MAC
};

/* 맵 정의: VIP -> Real Server 매핑 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct vip_definition);
    __type(value, struct real_server);
} lb_map SEC(".maps");

/* IP 체크섬 재계산 함수 (간단한 버전) */
static __always_inline void update_iph_checksum(struct iphdr *iph) {
    __u16 *next_iph_u16 = (__u16 *)iph;
    __u32 csum = 0;
    iph->check = 0;

    #pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(*iph) >> 1; i++) {
        csum += *next_iph_u16++;
    }

    iph->check = ~((csum & 0xffff) + (csum >> 16));
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. 이더넷 헤더 파싱
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // IP 패킷이 아니면 패스
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. IP 헤더 파싱
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // TCP가 아니면 패스 (예제 단순화)
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 3. TCP 헤더 파싱 (포트 확인용)
    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // 4. 맵 조회 (VIP:PORT 확인)
    struct vip_definition key = {};
    key.vip = iph->daddr;
    key.port = tcph->dest;

    struct real_server *dest = bpf_map_lookup_elem(&lb_map, &key);
    if (!dest) {
        return XDP_PASS; // 맵에 없으면 그냥 통과
    }

    // 5. 패킷 수정 (DNAT)
    // 목적지 IP를 백엔드 서버 IP로 변경
    iph->daddr = dest->ip;

    // 목적지 MAC 주소 변경
    __builtin_memcpy(eth->h_dest, dest->mac, 6);

    // 소스 MAC 주소는 내 인터페이스의 MAC으로 설정해야 하지만,
    // 여기서는 간단히 수정하지 않거나 필요 시 추가 구현

    // IP 체크섬 재계산
    update_iph_checksum(iph);

    // bpf_printk를 사용하여 디버깅 가능 (cat /sys/kernel/debug/tracing/trace_pipe)
    bpf_printk("Redirecting packet to Backend IP: %x\n", dest->ip);

    return XDP_TX; // 수정된 패킷을 들어온 인터페이스로 다시 내보냄 (혹은 XDP_REDIRECT)
}

char LICENSE[] SEC("license") = "GPL";