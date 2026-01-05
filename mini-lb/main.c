// main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// 인터페이스 이름 (실습 환경에 맞게 변경 필요, 예: lo, eth0)
#define LO_IFACE "lo"

static int ifindex;
static struct bpf_link *link = NULL;
static bool stop = false;

struct vip_definition {
    __u32 vip;
    __u32 port;
};

struct real_server {
    __u32 ip;
    unsigned char mac[6];
};

// 종료 시그널 처리 (Ctrl+C)
void sig_handler(int sig) {
    stop = true;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int map_fd;
    int err;

    // 1. 종료 시그널 등록
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 2. BPF 객체 열기
    obj = bpf_object__open_file("balancer.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // 3. BPF 프로그램 로드
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // 4. 맵 찾기
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "lb_map");
    if (!map) {
        fprintf(stderr, "ERROR: finding map failed\n");
        return 1;
    }
    map_fd = bpf_map__fd(map);

    // 5. 맵 데이터 채우기 (VIP -> Real Server)
    // 예제: 127.0.0.1:8080 -> 127.0.0.1 (테스트용, 실제 환경에 맞게 수정 필요)
    struct vip_definition key = {
        .vip = inet_addr("127.0.0.1"),
        .port = htons(8080)
    };

    struct real_server value = {
        .ip = inet_addr("10.0.0.2"), // 백엔드 IP
        .mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} // 백엔드 MAC
    };

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "ERROR: map update failed\n");
        return 1;
    }
    printf("Map populated: VIP 127.0.0.1:8080 -> Backend 10.0.0.2\n");

    // 6. XDP 프로그램 찾기 및 인터페이스에 부착
    prog = bpf_object__find_program_by_name(obj, "xdp_load_balancer");
    if (!prog) {
        fprintf(stderr, "ERROR: finding program failed\n");
        return 1;
    }

    ifindex = if_nametoindex(LO_IFACE);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: failed to find interface %s\n", LO_IFACE);
        return 1;
    }

    // XDP Attach (SKB 모드는 하드웨어 지원 없이도 작동하도록 함)
    err = bpf_program__attach_xdp(prog, ifindex); // 구버전 libbpf 스타일
    // 최신 libbpf에서는 bpf_xdp_attach 사용 권장, 여기서는 간단히 link 사용
    // link = bpf_program__attach_xdp(prog, ifindex);

    // 참고: 직접 attach 함수를 사용하여 XDP Flags 설정 (예: XDP_FLAGS_SKB_MODE)
    int prog_fd = bpf_program__fd(prog);
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err < 0) {
        fprintf(stderr, "ERROR: failed to attach XDP program: %s\n", strerror(-err));
        return 1;
    }

    printf("XDP Load Balancer attached on %s (Index: %d)\n", LO_IFACE, ifindex);
    printf("Press Ctrl+C to stop...\n");

    // 7. 무한 루프 (프로그램이 종료되면 XDP도 떨어질 수 있음)
    while (!stop) {
        sleep(1);
    }

    // 8. 정리 및 종료
    printf("Detaching XDP program...\n");
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);

    return 0;
}