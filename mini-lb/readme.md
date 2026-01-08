# 테스트 방법

docker exec -it client nc 192.168.10.1 50007

# 트러블 슈팅




# Network Architecture & Packet Flow

이 프로젝트는 **XDP(eBPF)**를 활용한 **DSR(Direct Server Return)** 로드 밸런서를 구현합니다.
일반적인 로드 밸런서(NAT)와 DSR 방식의 차이점, 그리고 패킷의 상세 흐름은 아래와 같습니다.

---

## Architecture Comparison (NAT vs DSR)

로드 밸런싱의 핵심은 "응답 패킷(Response)이 돌아오는 경로"에 있습니다.

```mermaid
graph TD
    %% 노드 정의
    Client(Client)
    LB(Load Balancer)
    Real(Real Server)

    subgraph Comparison [대역폭 비교]
        direction TB
        
        %% 1. NAT 방식 (일반)
        subgraph NAT_Mode [일반 LB ]
            direction TB
            C1(Client)
            L1(LB)
            R1(Real Server)
            
            C1 -- "요청 (1KB)" --> L1
            L1 -- "요청 (1KB)" --> R1
            
            R1 == "응답 (1GB) 🐢" ==> L1
            L1 == "응답 (1GB) 🐢" ==> C1
        end

        %% 2. DSR 방식 (Katran)
        subgraph DSR_Mode [ Katran ]
            direction TB
            C2(Client)
            K2(Katran)
            R2(Real Server)
            
            C2 -- "요청 (1KB)" --> K2
            K2 -- "요청 (1KB)" --> R2
            
            R2 == "응답 (1GB) " ==> C2
        end
    end

    %% 스타일링
    linkStyle 0,1,4,5 stroke-width:1px,stroke:gray;
    linkStyle 2,3,6 stroke-width:6px,stroke:red;
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