
```mermaid
graph TD
    %% 노드 정의
    Client[💻 Client<br/>10.111.220.11]
    Router[🔀 Router<br/>(Gateway)]
    Katran[🛡️ Katran (LB)<br/>10.111.221.11<br/>(XDP Program)]
    Real[🖥️ Real Server<br/>10.111.222.11<br/>(VIP: 192.168.10.1)]

    %% 스타일 정의
    style Client fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    style Router fill:#fff9c4,stroke:#fbc02d,stroke-width:2px
    style Katran fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style Real fill:#fce4ec,stroke:#880e4f,stroke-width:2px

    %% 흐름 1: 요청 (Client -> LB)
    Client -- "1. TCP SYN (Dst: VIP)" --> Router
    Router -- "2. Forward" --> Katran

    %% 흐름 2: 캡슐화 및 전달 (LB -> Real)
    Katran -- "3. XDP_TX (IPIP Encap)" --> Router
    Router -- "4. Forward (IPIP)" --> Real

    %% 흐름 3: 응답 (Real -> Client) - DSR
    Real -- "5. TCP SYN-ACK (Src: VIP)" --> Router
    Router -- "6. Forward (Direct)" --> Client

    %% 설명 링크 (투명)
    linkStyle 0,1 stroke:#0000FF,stroke-width:2px,fill:none;
    linkStyle 2,3 stroke:#0000FF,stroke-width:2px,stroke-dasharray: 5 5;
    linkStyle 4,5 stroke:#FF0000,stroke-width:3px;