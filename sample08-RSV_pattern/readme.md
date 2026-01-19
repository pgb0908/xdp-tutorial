# 테스트 방법
```shell
docker exec -it client nc 192.168.10.1 50007
```


# 트러블 슈팅




# Network Architecture & Packet Flow

이 프로젝트는 **XDP(eBPF)**를 활용한 **DSR(Direct Server Return)** 로드 밸런서를 구현합니다.
일반적인 로드 밸런서(NAT)와 DSR 방식의 차이점, 그리고 패킷의 상세 흐름은 아래와 같습니다.

---

## Architecture Comparison (NAT vs DSR)

로드 밸런싱의 핵심은 "응답 패킷(Response)이 돌아오는 경로"에 있습니다.

```mermaid
graph TD
    Client((Client))
    Router[Router / L3 Switch]
    LB[⚖️ Load Balancer<br/>]
    Real[Real Server]

    %% 물리적 연결 (DSR 구성과 똑같음!)
    Client --- Router
    Router --- LB
    Router --- Real

    %% 트래픽 흐름 (여기가 핵심!)
    %% 1. 요청
    Client -- "1. 요청" --> Router
    Router -- "2. 전달" --> LB
    
    %% 3. LB가 처리 후 다시 Router로 (Source NAT 필수!)
    LB -- "3. 주소 변환 후<br/>Router로 다시 보냄" --> Router
    Router -- "4. 서버로 전달" --> Real

    %% 5. 응답 (서버는 Router로 보내지만...)
    Real -- "5. 응답 (Dst: LB IP)" --> Router
    
    %% 6. Router는 이걸 다시 LB로 보냄 (비효율 발생!)
    Router -- "6. LB로 배달<br/>(헤어핀)" --> LB
    
    %% 7. LB가 최종 변환 후 나감
    LB -- "7. 최종 응답" --> Router
    Router -- "8. Client로" --> Client

    %% 스타일
    linkStyle 4,5,6,7 stroke:#ff0000,stroke-width:3px;
    style LB fill:#ffcdd2,stroke:#b71c1c,stroke-width:4px
```

##  Detailed Packet Flow (XDP Implementation)
XDP 프로그램(Katran)이 패킷을 어떻게 캡슐화(Encap) 하고, Real Server가 어떻게 변조(Spoofing) 하여 응답하는지 보여주는 상세 흐름도입니다.

- 🟦 Blue: 원본 요청 (Client → VIP)
- 🟩 Green: IPIP 터널링 (Katran → Real Server)
- 🟥 Red: DSR 응답 (Real Server [VIP] → Client)

```mermaid
graph TD
    %% ---------------------------------------
    %% 1. 노드 스타일 및 정의 (White Theme)
    %% ---------------------------------------
    classDef clientNode fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000;
    classDef routerNode fill:#fff9c4,stroke:#fbc02d,stroke-width:2px,color:#000;
    classDef katranNode fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000;
    classDef realNode   fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:#000;
    classDef container  fill:#ffffff,stroke:#666,stroke-width:2px,stroke-dasharray: 5 5,color:#000;

    Client("💻 <b>Client</b><br/>(10.111.220.11)"):::clientNode
    Real("🖥️ <b>Real Server</b><br/>(10.111.222.11)<br/>VIP: 192.168.10.1"):::realNode

    %% 논리적 그룹
    subgraph Logical_LB ["⚙️ Logical Load Balancer System"]
        direction TB
        Router("🔀 <b>Router</b><br/>(Gateway)"):::routerNode
        Katran("🛡️ <b>Katran</b> (XDP)<br/>(10.111.221.11)"):::katranNode
    end
    class Logical_LB container

    %% ---------------------------------------
    %% 2. 패킷 흐름 (화살표 길이 조정으로 겹침 방지)
    %% ---------------------------------------

    %% Step 1: Client -> Router
    Client -- "<b>[1. Request]</b><br/>(eth0 → eth2)<br/>🟦 <b>IP:</b> Client ➔ VIP" --> Router

    %% Step 2: Router -> Katran (길이 늘림 ---->)
    Router -- "<b>[2. Forward]</b><br/>(eth0 → eth0)<br/>🟦 <b>IP:</b> Client ➔ VIP" ----> Katran

    %% Step 3: Katran -> Router (Encap)
    %% 🟩: 겉포장(Outer), 🟦: 내용물(Inner)
    Katran -. "<b>[3. IPIP Encap]</b><br/>(eth0 → eth0)<br/>🟩 <b>Outer:</b> Katran ➔ Real<br/>🟦 <b>Inner:</b> Client ➔ VIP" .-> Router

    %% Step 4: Router -> Real (Forward Encap)
    %% 라우터와 Real 사이의 간격도 벌리기 위해 점선 연결
    Router -. "<b>[4. Forward IPIP]</b><br/>(eth1 → eth0)<br/>🟩 <b>Outer:</b> Katran ➔ Real<br/>🟦 <b>Inner:</b> Client ➔ VIP" .-> Real

    %% Step 5: Real -> Router (Decap & Spoof)
    %% 길이 늘림 (---->) : 빨간색 응답이 겹치지 않게 공간 확보
    Real -- "<b>[5. DSR Reply]</b><br/>(eth0 → eth1)<br/>🟥 <b>IP:</b> VIP ➔ Client<br/>(Not Real IP)" ----> Router

    %% Step 6: Router -> Client (Direct Return)
    Router -- "<b>[6. Return]</b><br/>(eth2 → eth0)<br/>🟥 <b>IP:</b> VIP ➔ Client" --> Client

    %% ---------------------------------------
    %% 3. 연결선 스타일링
    %% ---------------------------------------
    %% 요청 (파랑)
    linkStyle 0,1 stroke:#1565c0,stroke-width:2px,fill:none
    %% 터널링 (초록 점선)
    linkStyle 2,3 stroke:#2e7d32,stroke-width:2px,stroke-dasharray: 5 5
    %% 응답 (빨강)
    linkStyle 4,5 stroke:#c2185b,stroke-width:3px
```
