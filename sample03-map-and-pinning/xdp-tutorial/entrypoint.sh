#!/bin/bash

mount -t bpf bpf /sys/fs/bpf/

cd /xdp-tutorial

make clean
echo "clean all"

make
echo "make"

./xdp_loader xdp_prog_kern.o -S --dev eth0 --progname xdp_pass_func
echo "load xdp"

tail -f /dev/null