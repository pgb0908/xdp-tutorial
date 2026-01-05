# Makefile
CLANG ?= clang
CC ?= gcc
BPF_CFLAGS ?= -O2 -g -target bpf
USER_CFLAGS ?= -O2 -g -Wall
LIBS ?= -lbpf -lelf

all: balancer.bpf.o lb_loader

# 1. 커널용 BPF 오브젝트 파일 컴파일
balancer.bpf.o: balancer.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c balancer.bpf.c -o balancer.bpf.o

# 2. 유저스페이스 로더 컴파일
lb_loader: main.c
	$(CC) $(USER_CFLAGS) main.c -o lb_loader $(LIBS)

clean:
	rm -f *.o lb_loader