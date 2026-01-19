#!/bin/bash

mount -t bpf bpf /sys/fs/bpf/

cd /xdp-tutorial

ip link add link eth0 name eth0.100 type vlan id 100
ip addr add 10.10.100.10/24 dev eth0.100
ip -6 addr add fc00:100::10/64 dev eth0.100
ip link set up dev eth0.100
mount -t bpf bpf /sys/fs/bpf/

make clean
echo "clean all"

make
echo "make"

./xdp_loader xdp_prog_kern.o -S --dev eth0 --progname xdp_parser_func
echo "load xdp"

tail -f /dev/null