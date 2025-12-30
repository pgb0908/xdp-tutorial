TARGET := xdp_pass.o
SRC := xdp_pass.c

# Clang을 사용하여 BPF 타겟으로 컴파일
# -O2: 최적화 (BPF 검증기를 통과하기 위해 필수)
# -target bpf: BPF 아키텍처용으로 컴파일
# -c: 오브젝트 파일 생성
# -g: 디버깅 정보 포함
all: $(TARGET)

$(TARGET): $(SRC)
	clang -O2 -g -target bpf -c $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
