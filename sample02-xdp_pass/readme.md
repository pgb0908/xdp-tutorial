
테스트 방법
```shell

docker exec -it xdp-receiver xdp-loader load eth0 xdp_pass.o
docker exec -it xdp-receiver xdp-loader status

docker exec -it xdp-sender ping 172.20.0.10

docker exec -it xdp-receiver xdp-loader unload eth0 -a
docker exec -it xdp-receiver xdp-loader load eth0 xdp_drop.o
docker exec -it xdp-receiver xdp-loader status

docker exec -it xdp-sender ping 172.20.0.10
```

```shell
llvm-objdump -S xdp_pass.o
```

```shell
xdp_pass_kern.o:	file format ELF64-BPF

Disassembly of section xdp:
xdp_prog_simple:
; {
       0:	b7 00 00 00 02 00 00 00 	r0 = 2
; return XDP_PASS;
       1:	95 00 00 00 00 00 00 00 	exit
```

iProute2는 표준 ip 도구와 함께 사용할 수 있는 libbpf 기반 BPF 로딩 기능을 제공
따라서 이 경우 "xdp"라는 이름의 ELF 섹션이 포함된 ELF 파일 xdp_pass.o를 다음과 같이 로드할 수 있음
```shell
ip link set dev lo xdpgeneric obj xdp_pass.o sec xdp
```
iProute2 외에도 xdp의 경우 xdp-tool에서 제공하는 xdp-loader를 통해 xdp 프로그램을 쉽게 로딩할 수 있다.
또한 xdp-loader를 통해 네트워크 인터페이스에 등록된 xdp 프로그램 확인도 가능하다
```shell
xdp-loader load eth0 xdp_pass.o
xdp-loader status

xdp-loader load eth0 xdp_drop.o
```