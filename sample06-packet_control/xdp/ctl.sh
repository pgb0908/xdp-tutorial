#!/bin/bash

# 사용법: ./ctl.sh [drop|s1|s2]

MODE=$1

if [ "$MODE" == "drop" ]; then
    echo "Applying: DROP ALL"
    VALUE="0 0 0 0"
elif [ "$MODE" == "s1" ]; then
    echo "Applying: SERVER 1"
    VALUE="1 0 0 0"
elif [ "$MODE" == "s2" ]; then
    echo "Applying: SERVER 2"
    VALUE="2 0 0 0"
else
    echo "Usage: $0 [drop|s1|s2]"
    exit 1
fi

# 복잡한 명령어는 여기서 한 번만 작성
bpftool map update name config_map key 0 0 0 0 value $VALUE