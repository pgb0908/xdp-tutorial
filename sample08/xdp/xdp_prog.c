#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

// BPF Map 정의 (Array 타입, 크기 1)
// key 0번의 값을 통해 모드를 변경합니다.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

// 모드 상수 정의
#define MODE_DROP    0
#define MODE_SERVER1 1
#define MODE_SERVER2 2

// 서버 IP 주소 (Network Byte Order: Little Endian 환경 가정 시 역순 주의)
// Server 1: 10.20.20.100 -> 0x6414140A
// Server 2: 10.20.20.200 -> 0xC814140A
#define IP_SERVER1 0x6414140A 
#define IP_SERVER2 0xC814140A

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. 이더넷 헤더 파싱
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // IPv4가 아니면 그냥 통과
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. IP 헤더 파싱
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 3. BPF Map에서 현재 모드 읽기
    __u32 key = 0;
    __u32 *mode = bpf_map_lookup_elem(&config_map, &key);
    
    // 맵 값을 읽지 못하면 기본적으로 차단(안전을 위해)
    if (!mode) return XDP_DROP;

    // 4. 모드에 따른 로직 수행
    if (*mode == MODE_DROP) {
        // 모든 패킷 차단
        return XDP_DROP;
    } 
    else if (*mode == MODE_SERVER1) {
        // Server 1 IP(10.20.20.100)로 가는 것만 허용
        if (iph->daddr == IP_SERVER1) return XDP_PASS;
        return XDP_DROP;
    } 
    else if (*mode == MODE_SERVER2) {
        // Server 2 IP(10.20.20.200)로 가는 것만 허용
        if (iph->daddr == IP_SERVER2) return XDP_PASS;
        return XDP_DROP;
    }

    // 그 외 경우는 기본 DROP
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";