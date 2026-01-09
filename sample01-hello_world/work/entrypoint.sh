#!/bin/bash

# 1. 절대 경로로 이동 (안전하게)
cd /work

# 2. [핵심] 기존 빌드 파일 삭제!
# 호스트에 남아있는 옛날 .o 파일을 지워야 새 코드가 컴파일됩니다.
make clean

# 3. 새로 컴파일
make

# 4. 로더 실행
./my_bpf_loader minimal.bpf.o