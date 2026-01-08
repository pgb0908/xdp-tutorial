docker exec -it xdp-sender ping 172.20.0.10


llvm-objdump -S xdp_pass.o
```shell
xdp_pass_kern.o:	file format ELF64-BPF

Disassembly of section xdp:
xdp_prog_simple:
; {
       0:	b7 00 00 00 02 00 00 00 	r0 = 2
; return XDP_PASS;
       1:	95 00 00 00 00 00 00 00 	exit
```


```shell
ip link set dev lo xdpgeneric obj xdp_pass.o sec xdp
```

```shell
xdp-loader load eth0 xdp_pass.o
```