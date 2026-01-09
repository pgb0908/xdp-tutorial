#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 우리가 찾을 대상 프로세스 이름
const char target_name[] = "echo";

SEC("tp/syscalls/sys_enter_write")
int handle_write(void *ctx)
{
    char comm[16];

    // 무수한 로그 중 특정 커맨드만 필터링 하기 위한 코드
    bpf_get_current_comm(&comm, sizeof(comm));
    for (int i = 0; i < sizeof(target_name); i++) {
        if (target_name[i] == '\0') break;
        if (comm[i] != target_name[i]) return 0;
    }

    // 선택된 command로만 로그 생성
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("Success! Deteced 'echo' command (PID: %d)\n", pid);

    return 0;
}