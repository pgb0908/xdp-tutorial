#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * SEC("xdp") 매크로는 이 함수가 XDP 훅(hook)에 들어갈 것임을 
 * BPF 로더에게 알려주는 역할을 합니다.
 */
SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
    /* * XDP_PASS: 패킷을 커널 네트워크 스택으로 그대로 올려보냅니다.
     * 즉, 아무런 조작 없이 평소처럼 처리되도록 합니다.
     */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
