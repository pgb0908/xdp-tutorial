# Makefile
CLANG ?= clang
CC ?= gcc
BPF_CFLAGS ?= -O2 -g -target bpf

all: xdp_lb.o loader

# 1. 커널용 BPF 코드 컴파일 (.o 파일 생성)
xdp_lb.o: xdp_lb.c common.h
	$(CLANG) $(BPF_CFLAGS) -c xdp_lb.c -o xdp_lb.o

# 2. 유저용 C 로더 컴파일 (실행 파일 생성)
# -lbpf -lelf 가 반드시 필요합니다.
loader: loader.c common.h
	$(CC) -O2 -g loader.c -o loader -lbpf -lelf

clean:
	rm -f xdp_lb.o loader