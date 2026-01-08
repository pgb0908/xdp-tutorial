# 컴파일할 대상 파일들의 목록 (여기에 계속 추가하면 됩니다)
TARGETS := xdp_pass.o xdp_drop.o

# 컴파일러 설정
CLANG := clang
CFLAGS := -O2 -g -target bpf -c

# 'make'를 입력하면 실행되는 기본 타겟
all: $(TARGETS)

# [패턴 규칙]
# %.o : %.c  -> .c 파일이 있으면 그에 맞는 .o 파일을 만드는 규칙입니다.
# $<  -> 입력 파일 (예: xdp_pass.c)
# $@  -> 출력 파일 (예: xdp_pass.o)
%.o: %.c
	$(CLANG) $(CFLAGS) $< -o $@

# 생성된 파일들 삭제
clean:
	rm -f $(TARGETS)