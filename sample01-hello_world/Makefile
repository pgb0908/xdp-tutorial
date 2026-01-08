# 컴파일러 설정
CLANG ?= clang
CC ?= gcc

# 현재 시스템의 아키텍처 감지 (x86_64 -> x86, aarch64 -> arm64)
# bpf_tracing.h를 사용할 때 __TARGET_ARCH_xxx 매크로가 필요하기 때문입니다.
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# 결과물 파일 이름 정의
BPF_SRC := minimal.bpf.c
BPF_OBJ := minimal.bpf.o
LOADER_SRC := loader.c
LOADER_BIN := loader

# 플래그 설정
# -g: 디버그 정보 포함 (BTF 생성에 필수)
# -O2: 최적화 (BPF는 항상 최적화가 필요함)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
LOADER_CFLAGS := -g -O2
LIBS := -lbpf -lelf

# 가짜 타겟 정의 (파일 이름이 아님을 명시)
.PHONY: all clean

# 기본 타겟: make만 치면 실행됨
all: $(BPF_OBJ) $(LOADER_BIN)

# 1. BPF 오브젝트 파일 컴파일 규칙
$(BPF_OBJ): $(BPF_SRC)
	@echo "  CLANG   $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 2. 로더 프로그램 컴파일 규칙
$(LOADER_BIN): $(LOADER_SRC)
	@echo "  CC      $@"
	$(CC) $(LOADER_CFLAGS) -o $@ $< $(LIBS)

# 청소 규칙: make clean 시 실행됨
clean:
	@echo "  CLEAN"
	rm -f $(BPF_OBJ) $(LOADER_BIN)