
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