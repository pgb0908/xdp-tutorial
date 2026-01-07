FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# 1. 필수 패키지 설치
# clang, llvm: BPF 컴파일러
# libbpf-dev, libelf-dev: BPF 라이브러리 및 ELF 파싱
# iproute2: ip link 명령어로 XDP 로드
# linux-headers-generic: 커널 헤더 (호스트와 버전이 다를 수 있어 주의 필요)
# gcc-multilib, make, pkg-config: 빌드 도구
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    make \
    gcc \
    gcc-multilib \
    pkg-config \
    iproute2 \
    git \
    linux-headers-generic \
    sudo \
    m4 \
    libpcap-dev \
    linux-tools-common \
    linux-tools-generic \
    xdp-tools \
    libxdp-dev \
    tcpdump \
    net-tools \
    iptables \
    iputils-ping \
    netcat-openbsd \
    ethtool \
    && rm -rf /var/lib/apt/lists/*


# 2. 작업 디렉토리 설정
WORKDIR /xdp-tutorial

# 3. 기본 명령어
CMD ["/bin/bash"]
