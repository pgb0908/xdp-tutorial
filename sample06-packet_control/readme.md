패킷의 내부 데이터(헤더)를 들여다보고 판단하는 로직을 작성

```mermaid
graph LR
    %% 스타일 정의
    classDef client fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef xdp fill:#fff9c4,stroke:#fbc02d,stroke-width:4px;
    classDef server fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef net fill:#f5f5f5,stroke:#9e9e9e,stroke-dasharray: 5 5;
    classDef map fill:#e1bee7,stroke:#8e24aa,stroke-width:2px,stroke-dasharray: 5 5;
    classDef user fill:#eeeeee,stroke:#616161,stroke-width:2px,stroke-dasharray: 0;

    subgraph "Network A (10.10.10.0/24)"
        Client(Client Container<br>10.10.10.10):::client
    end

    subgraph "Network B (10.20.20.0/24)"
        S1(Server 1<br>10.20.20.100):::server
        S2(Server 2<br>10.20.20.200):::server
    end

    %% 사용자 터미널 (외부 커맨드)
    User((User Terminal<br>bpftool command)):::user

    %% XDP 노드 및 연결
    Client --"Traffic"--> eth0
    
    subgraph "XDP Node (Router)"
        direction TB
        
        %% BPF Map (데이터 저장소)
        Map[("BPF Map<br>(config_map)")]:::map

        eth0[eth0: 10.10.10.2<br><b>🔥 XDP Attached Here</b>]:::xdp
        eth1[eth1: 10.20.20.2]:::xdp
        
        eth0 --"PASS: Routing"--> eth1
    end

    %% 제어 흐름 (Control Plane)
    User == "1. Update Map" ==> Map
    Map -.-> |"2. Read Policy"| eth0

    %% 네트워크 흐름
    eth1 --> S1
    eth1 --> S2

    %% 주석 스타일
    style eth0 fill:#ffccbc,stroke:#d84315
```

```shell
docker exec -it xdp-node /bin/bash
./ctl.sh s1    # 서버 1 모드로 변경
./ctl.sh drop  # 드랍 모드로 변경

bpftool map dump name config_map
```

```shell
docker exec -it xdp-node bpftool map update name config_map key 0 0 0 0 value 0 0 0 0
docker exec -it client ping 10.20.20.100
docker exec -it client ping 10.20.20.200
```

```shell
docker exec -it xdp-node bpftool map update name config_map key 0 0 0 0 value 1 0 0 0
docker exec -it client ping 10.20.20.100
docker exec -it client ping 10.20.20.200
```

```shell
docker exec -it xdp-node bpftool map update name config_map key 0 0 0 0 value 2 0 0 0
docker exec -it client ping 10.20.20.100
docker exec -it client ping 10.20.20.200
```
```shell
docker exec -it xdp-node bpftool map dump name config_map
```
이더넷 헤더 파싱 및 패킷 크기 검증
1. ctx->data(시작)와 ctx->data_end(끝) 포인터
2. data + sizeof(struct ethhdr) > data_end 조건을 검사하여 패킷이 너무 짧으면 패킷을 드롭하거나 종료
3. 이더넷 프로토콜 타입을 확인하여 다음 단계로 넘어갈 준비


```shell
docker exec -it xdp-sender ping -c 4 172.20.0.10
docker exec -it xdp-sender ping6 -c 4 fd00:dead:cafe::10
docker exec -it xdp-sender ping6 -c 4 -I eth0.100 fc00:100::10
```
