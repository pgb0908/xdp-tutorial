#!/bin/bash

# 1. 기본 라우팅 (Client로 돌아가는 길)
ip route del default
# 기존 default가 있다면 에러날 수 있으니 via 추가 방식 사용
ip route add 10.111.220.0/24 via 10.111.222.12

# 2. VIP를 Loopback에 설정 (이게 없으면 자기 패킷 아니라고 버림)
ip addr add 192.168.10.1/32 dev lo

# 3. IPIP 터널 설정
ip link add name ipip0 type ipip external
ip link set up dev ipip0
ip addr add 127.0.0.42/32 dev ipip0

# 4. [핵심] 보안 설정 해제 (rp_filter & accept_local)
# accept_local=1 : 내 IP(VIP)를 달고 외부에서 들어오는 패킷 허용 (Martian Packet 해결)
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.all.accept_local=1
sysctl -w net.ipv4.conf.eth0.accept_local=1
sysctl -w net.ipv4.conf.ipip0.rp_filter=0

# 5. 수신 체크섬 끄기 (IPIP 패킷 오류 무시)
ethtool -K eth0 rx off
ethtool -K ipip0 rx off

# 6. Python 서버 백그라운드 실행 (&)
echo "Starting Python Echo Server..."
python3 -u /data/echo.py &

tail -f /dev/null