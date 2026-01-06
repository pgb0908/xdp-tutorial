#!/bin/bash

# send everything to katran
ip route del default
ip route add default via 10.111.221.11

sysctl -w net.ipv4.conf.all.rp_filter=0

tail -f /dev/null