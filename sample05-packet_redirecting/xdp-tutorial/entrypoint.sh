#!/bin/bash

cd /xdp-tutorial

mount -t bpf bpf /sys/fs/bpf/

arp -s 172.20.1.2 02:00:00:00:00:02
arp -s 172.20.2.2 02:00:00:00:00:04

make clean
echo "clean all"

make
echo "make"

./xdp_loader xdp_prog_kern.o -S --dev eth0 --progname xdp_router_func
./xdp_loader xdp_prog_kern.o -S --dev eth1 --progname xdp_router_func

tail -f /dev/null