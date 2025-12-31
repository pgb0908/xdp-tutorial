# 컴파일러 설정
CLANG ?= clang
CC ?= gcc

# 컴파일 플래그 설정
# -g: 디버깅 정보 포함
# -O2: 최적화 레벨 2 (BPF 검증기를 통과하기 위해 보통 필수)
# -Wall: 경고 메시지 출력
CFLAGS := -O2 -g -Wall -I. -I./common

# 링크할 라이브러리 (libxdp, libbpf, libelf, zlib)
LDLIBS := -lxdp -lbpf -lelf -lz

# 타겟 이름 정의
XDP_OBJ := xdp_prog_kern.o
USER_TARGET := xdp_load_and_stats

# Common 폴더의 소스 및 오브젝트 파일 정의
COMMON_DIR := common
COMMON_OBJS := $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o

# 기본 타겟: make를 치면 실행되는 부분
all: $(XDP_OBJ) $(USER_TARGET)

# 1. 커널 사이드 BPF 프로그램 컴파일 (Clang 사용, target bpf)
$(XDP_OBJ): xdp_prog_kern.c common_kern_user.h
	$(CLANG) -O2 -g -target bpf -c $< -o $@

# 2. 유저 사이드 프로그램 컴파일 및 링크
# common 오브젝트들과 함께 컴파일합니다.
$(USER_TARGET): xdp_load_and_stats.c $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# 3. Common 디렉토리 내의 C 파일 컴파일 규칙
$(COMMON_DIR)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 클린업: 생성된 파일 삭제
clean:
	rm -f $(USER_TARGET)
	rm -f *.o
	rm -f $(COMMON_DIR)/*.o
