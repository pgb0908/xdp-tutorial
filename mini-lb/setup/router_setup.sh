#!/bin/bash

# 1. 라우팅 설정
ip route del default
ip route add default via 10.111.221.11

# 2. IP 포워딩 활성화 (필수)
sysctl -w net.ipv4.ip_forward=1

# 3. 방화벽 초기화 및 허용
iptables -P FORWARD ACCEPT
iptables -F
iptables -t nat -F

# 4. rp_filter 해제 (패킷 드랍 방지)
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.eth0.rp_filter=0
sysctl -w net.ipv4.conf.eth1.rp_filter=0
sysctl -w net.ipv4.conf.eth2.rp_filter=0

# 5. 수신 체크섬 검사 끄기 (Client 패킷 수용)
ethtool -K eth2 rx off

# 6. [중요] ARP 테이블 갱신을 위해 Katran에게 인사하기
# (Katran이 켜질 때까지 잠시 대기 후 실행)
(sleep 5 && ping -c 2 10.111.221.11) &

tail -f /dev/null