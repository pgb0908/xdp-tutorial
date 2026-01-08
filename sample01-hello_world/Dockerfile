# 1. 베이스 이미지 선택 (Ubuntu 22.04 LTS 사용)
FROM ubuntu:22.04

# 2. 패키지 설치 시 인터랙션 방지 설
ENV DEBIAN_FRONTEND=noninteractive

# 3. 필수 빌드 도구 및 BPF 라이브러리 설치
# clang, llvm: BPF 컴파일용
# gcc, make: 로더 컴파일용
# libbpf-dev, libelf-dev: BPF 개발 헤더 및 라이브러리
RUN apt-get update && \
    apt-get install -y \
    clang \
    llvm \
    gcc \
    make \
    libbpf-dev \
    libelf-dev \
    pkg-config \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# 4. 작업 디렉토리 설정
WORKDIR /app

# 5. 소스 코드 복사 (Makefile, .c 파일들)
COPY . .

# 6. 빌드 실행 (Makefile 이용)
RUN make

# 7. 컨테이너 실행 시 기본 명령어
# 로더를 실행하여 BPF를 로드합니다.
CMD ["./my_bpf_loader", "minimal.bpf.o"]