#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h" // 공통 구조체 사용

// 사용법: ./loader <ifname> <vip> <real_ip> <dst_mac>
// 예: ./loader eth0 192.168.10.1 10.111.222.11 02:42:0a:6f:dd:0c

// MAC 주소 파싱 헬퍼 함수
int parse_mac(const char *str, unsigned char *mac) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ? 0 : -1;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, map_fd;
    int ifindex;
    struct lb_config config = {0};
    int err;

    if (argc < 5) {
        fprintf(stderr, "Usage: %s <ifname> <vip> <real_ip> <dst_mac>\n", argv[0]);
        return 1;
    }

    // 1. 인자 파싱 및 데이터 준비
    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    inet_pton(AF_INET, argv[2], &config.lb_vip);       // VIP 변환
    inet_pton(AF_INET, argv[3], &config.real_server_ip); // Real IP 변환
    if (parse_mac(argv[4], config.dst_mac) < 0) {      // MAC 변환
        fprintf(stderr, "Invalid MAC address\n");
        return 1;
    }
    
    // 내 MAC 주소 가져오는 로직은 생략 (간소화를 위해 00으로 두거나 하드코딩 가능)
    // 실제 구현시엔 ioctl(SIOCGIFHWADDR) 등을 사용해야 함
    // 여기서는 임시로 Gateway MAC과 동일하게 설정하거나 더미 값 사용
    memcpy(config.src_mac, config.dst_mac, 6); 

    // 2. BPF 객체 열기 및 로드 (xdp_lb.o 파일 필요)
    obj = bpf_object__open_file("xdp_lb.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // 3. 프로그램 찾기
    prog = bpf_object__find_program_by_name(obj, "xdp_load_balancer");
    if (!prog) {
        fprintf(stderr, "ERROR: finding XDP program failed\n");
        return 1;
    }

    // 4. 맵 찾기 및 설정값 업데이트
    map = bpf_object__find_map_by_name(obj, "lb_map");
    if (!map) {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return 1;
    }
    map_fd = bpf_map__fd(map);

    __u32 key = 0;
    if (bpf_map_update_elem(map_fd, &key, &config, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        return 1;
    }
    printf("Config updated in BPF map!\n");

    // 5. XDP 프로그램 인터페이스에 부착 (Attach)
    // bpf_prog_attach 또는 bpf_link 사용. 최신 libbpf 방식 권장.
    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: Attaching XDP program failed\n");
        return 1;
    }

    printf("XDP Attached to %s (Index: %d). Press Ctrl+C to stop.\n", ifname, ifindex);

    // 6. 무한 대기 (종료 시 자원 해제)
    while (1) {
        sleep(1);
    }

    // 실제로는 Signal Handler를 등록하여 종료 시 아래 코드가 실행되게 해야 함
    // bpf_link__destroy(link);
    // bpf_object__close(obj);
    return 0;
}