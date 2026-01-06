#!/bin/bash

# The VIP is directed to the katran instance

cd /xdp
make clean
make

sudo ./loader eth0 192.168.10.1 10.111.222.11 02:42:0a:6f:dd:0c
sysctl -w net.ipv4.conf.all.rp_filter=0

tail -f /dev/null