// loader.c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int err;

    // 1. 인자 확인
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object_file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];

    // 시그널 핸들러 설정
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Loading BPF object file: %s\n", filename);

    // 2. BPF 오브젝트 파일 열기 (Open)
    // 스켈레톤이 없으므로 파일 경로를 직접 지정해 엽니다.
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // 3. BPF 프로그램 로드 (Load)
    // 커널 검증기를 거쳐 프로그램을 로드합니다.
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed: %d\n", err);
        goto cleanup;
    }

    // 4. 프로그램 연결 (Attach)
    // 오브젝트 파일 안에 정의된 모든 프로그램(SEC)을 찾아서 연결합니다.
    // 예: sys_enter_write 같은 트레이스포인트
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);

        // 자동 연결이 가능한 섹션(SEC)인지 확인하고 연결
        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "ERROR: attaching program '%s' failed\n", prog_name);
            link = NULL;
            goto cleanup;
        }
        printf("Attached program: %s\n", prog_name);
    }

    printf("Successfully loaded! Press Ctrl+C to stop.\n");

    // 5. 이벤트 루프
    while (!exiting) {
        sleep(1);
    }

    cleanup:
        // 6. 정리 (Close)
        // bpf_object__close는 연결된 링크와 로드된 맵 등을 모두 정리합니다.
        bpf_object__close(obj);
    return 0;
}