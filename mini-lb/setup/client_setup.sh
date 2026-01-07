#!/bin/bash

echo "hello"

# [핵심] 송신 체크섬 오프로딩 끄기 (안 하면 라우터가 버림)
ethtool -K eth0 tx off

# [핵심] 나가는 패킷의 체크섬을 강제로 채워넣기 (가장 확실한 방법)
iptables -t mangle -A POSTROUTING -p tcp -j CHECKSUM --checksum-fill

# 라우팅 설정
ip route del default
ip route add default via 10.111.220.12

tail -f /dev/null