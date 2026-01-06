import socket

HOST = ''
PORT = 50007
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # 포트 재사용 옵션 (재시작 시 에러 방지)
s.bind((HOST, PORT))
s.listen(1)
print('Listening on port', PORT)

# 무한 루프를 통해 계속 연결을 받도록 수정
while True:
    conn, addr = s.accept()
    # 쉼표(,)를 사용하면 튜플도 출력 가능
    print('Connected by', addr)

    with conn: # with문을 쓰면 연결이 끝나면 알아서 close됨
        while True:
            data = conn.recv(1024)
            if not data: break
            conn.sendall(data)