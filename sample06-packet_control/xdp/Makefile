CLANG ?= clang
CC ?= gcc
BPF_CFLAGS ?= -O2 -g -target bpf

all: xdp_prog.o

# [수정됨] 타겟 이름을 xdp_lb.o에서 xdp_prog.o로 변경
xdp_prog.o: xdp_prog.c
	$(CLANG) $(BPF_CFLAGS) -c xdp_prog.c -o xdp_prog.o

clean:
	rm -f xdp_prog.o