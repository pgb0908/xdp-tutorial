# Network Architecture & Packet Flow

이 프로젝트는 **XDP(eBPF)**를 활용한 **DSR(Direct Server Return)** 로드 밸런서를 구현합니다.
일반적인 로드 밸런서(NAT)와 DSR 방식의 차이점, 그리고 패킷의 상세 흐름은 아래와 같습니다.

---

## Architecture Comparison (NAT vs DSR)

로드 밸런싱의 핵심은 "응답 패킷(Response)이 돌아오는 경로"에 있습니다.

### A. 일반적인 로드 밸런서 (NAT/Proxy 방식)
응답 트래픽이 반드시 로드 밸런서(LB)를 **다시 거쳐야** 합니다.
대용량 트래픽 처리 시 **LB가 병목(Bottleneck)**이 될 수 있습니다.

```mermaid
graph TD
    %% 노드 정의
    Client(Client)
    Router(Router / Gateway)
    LB(Load Balancer)
    Real(Real Server)

    %% 스타일
    style LB fill:#ffcdd2,stroke:#b71c1c,stroke-width:4px
    style Router fill:#fff9c4,stroke:#fbc02d,stroke-width:2px

    %% 흐름 (NAT)
    Real -- "1. 응답 (Dst: Client)" --> Router
    Router -- "2. LB로 전달 (Forward)" --> LB
    LB -- "3. 주소 변환 (SNAT)" --> LB
    LB -- "4. 다시 Router로 (Return)" --> Router
    Router -- "5. Client로 (Final)" --> Client

    %% 링크 스타일
    linkStyle 0,1,2,3,4 stroke:#FF0000,stroke-width:3px;

```

### B.우리가 구현한 Katran (DSR 방식)
응답 트래픽이 LB를 거치지 않고 Router를 통해 Client로 직접(Direct) 전달됩니다. LB의 부하를 획기적으로 줄여 압도적인 성능을 제공합니다.


```mermaid
graph TD
    %% 노드 정의
    Client(Client)
    Router(Router / Gateway)
    LB(Katran)
    Real(Real Server)

    %% 스타일
    style LB fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,stroke-dasharray: 5 5
    style Router fill:#fff9c4,stroke:#fbc02d,stroke-width:2px

    %% 흐름 (DSR)
    Real -- "1. 응답 (Dst: Client)" --> Router
    Router -- "2. 바로 Client로! (Direct)" --> Client

    %% 끊어진 링크 (LB 안 감)
    Router -.- X(LB 안 들름) -.-> LB

    %% 링크 스타일
    linkStyle 0,1 stroke:#FF0000,stroke-width:3px;
    linkStyle 2 stroke:#ccc,stroke-width:1px;
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