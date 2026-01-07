
```mermaid
graph TD
    %% 노드 정의
    Client["💻 Client<br/>(10.111.220.11)"]
    Real["🖥️ Real Server<br/>(10.111.222.11)<br/>VIP: 192.168.10.1"]

    %% 논리적 그룹 (Router + Katran)
    subgraph Logical_LB ["⚙️ Logical Load Balancer System"]
        direction TB
        Router["🔀 Router<br/>(Gateway)"]
        Katran["🛡️ Katran (XDP)<br/>(10.111.221.11)"]
    end

    %% 스타일 정의
    style Client fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    style Real fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    style Logical_LB fill:#fff3e0,stroke:#e65100,stroke-width:2px,stroke-dasharray: 5 5
    style Router fill:#fff9c4,stroke:#fbc02d,stroke-width:2px
    style Katran fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px

    %% 1. 요청 흐름 (Client -> Router -> Katran)
    Client -- "1. TCP SYN<br/>(eth0 ↔ eth2)" --> Router
    Router -- "2. Forward<br/>(eth0 ↔ eth0)" --> Katran

    %% 2. 처리 및 전달 (Katran -> Router -> Real)
    Katran -. "3. XDP_TX (IPIP)<br/>(eth0 ↔ eth0)" .-> Router
    Router -- "4. Forward (IPIP)<br/>(eth1 ↔ eth0)" --> Real

    %% 3. 직접 응답 (Real -> Router -> Client)
    Real -- "5. TCP SYN-ACK<br/>(eth0 ↔ eth1)" --> Router
    Router -- "6. Return (Direct)<br/>(eth2 ↔ eth0)" --> Client

    %% 링크 스타일
    linkStyle 0,1 stroke:#0000FF,stroke-width:2px;
    linkStyle 2,3 stroke:#0000FF,stroke-width:2px,stroke-dasharray: 5 5;
    linkStyle 4,5 stroke:#FF0000,stroke-width:3px;