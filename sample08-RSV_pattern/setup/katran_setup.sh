#!/bin/bash

# The VIP is directed to the katran instance

cd /xdp
make clean
make

# 1. Router와 통신하여 ARP 테이블 갱신
ping -c 1 10.111.221.12 > /dev/null 2>&1

# 2. Router의 실제 MAC 주소 자동 추출
ROUTER_MAC=$(arp -n | grep 10.111.221.12 | awk '{print $3}')

if [ -z "$ROUTER_MAC" ]; then
    echo "Error: Router MAC not found!"
    # 실패 시 하드코딩된 값이라도 시도하거나 종료 (여기선 종료)
    exit 1
fi

echo "Found Router MAC: $ROUTER_MAC"

# 3. 로더 실행 (추출한 MAC 사용)
sudo ./loader eth0 192.168.10.1 10.111.222.11 $ROUTER_MAC

# rp_filter 해제
sysctl -w net.ipv4.conf.all.rp_filter=0

tail -f /dev/null