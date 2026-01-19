# Makefile
CLANG ?= clang
CC ?= gcc
BPF_CFLAGS ?= -O2 -g -target bpf

all: lb.o

# 1. 커널용 BPF 코드 컴파일 (.o 파일 생성)
xdp_lb.o: lb.c parse_helpers.h
	$(CLANG) $(BPF_CFLAGS) -c lb.c -o lb.o

clean:
	rm -f xdp_lb.o