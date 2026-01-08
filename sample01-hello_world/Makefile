# 컴파일러 설정
CLANG ?= clang
CC ?= gcc

# 현재 시스템의 아키텍처 감지
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# [수정됨] 헤더 파일을 찾기 위한 아키텍처 경로 변수 추가
# 예: /usr/include/x86_64-linux-gnu
ARCH_INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu

# 결과물 파일 이름 정의
BPF_SRC := minimal.bpf.c
BPF_OBJ := minimal.bpf.o
LOADER_SRC := my_bpf_loader.c
LOADER_BIN := my_bpf_loader

# 플래그 설정
# [수정됨] $(ARCH_INCLUDES)를 끝에 추가했습니다.
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(ARCH_INCLUDES)
LOADER_CFLAGS := -g -O2
LIBS := -lbpf -lelf

# 가짜 타겟 정의
.PHONY: all clean

# 기본 타겟
all: $(BPF_OBJ) $(LOADER_BIN)

# 1. BPF 오브젝트 파일 컴파일 규칙
$(BPF_OBJ): $(BPF_SRC)
	@echo "  CLANG   $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 2. 로더 프로그램 컴파일 규칙
$(LOADER_BIN): $(LOADER_SRC)
	@echo "  CC      $@"
	$(CC) $(LOADER_CFLAGS) -o $@ $< $(LIBS)

# 청소 규칙
clean:
	@echo "  CLEAN"
	rm -f $(BPF_OBJ) $(LOADER_BIN)