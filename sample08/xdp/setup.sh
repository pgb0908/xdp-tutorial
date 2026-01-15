#!/bin/bash

# The VIP is directed to the katran instance

cd /xdp
make clean
make

sysctl -w net.ipv4.ip_forward=1
ip link set dev eth0 xdpobj xdp_prog.o sec xdp

xdp-loader load eth0 xdp_prog.o
xdp-loader status

tail -f /dev/null