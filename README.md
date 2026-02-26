# 🚀 DPI Backend Service

## 📌 Overview

This project implements a **Deep Packet Inspection (DPI) backend
service** using:

-   ⚡ FastAPI (Async API Layer)
-   🔁 Flow-based Connection Tracking
-   🧠 TLS SNI Classification
-   🚫 Rule-based Blocking Engine (Redis)
-   📊 Real-time Statistics Tracking
-   🧵 Async Worker Dispatcher Architecture

It is a microservice adaptation of a high-performance DPI engine.

------------------------------------------------------------------------

# 🧠 What is DPI?

Deep Packet Inspection inspects:

-   Source / Destination IP
-   Ports
-   Protocol (TCP/UDP)
-   Payload
-   TLS SNI (Server Name Indication)
-   HTTP Host Header
-   DNS Query

Even HTTPS traffic exposes domain names inside the TLS Client Hello
(SNI).

------------------------------------------------------------------------

# 🏗 System Architecture

## 🔹 High-Level Flow

``` mermaid
flowchart TD
    A[Client Packet JSON] --> B[/POST /ingest/]
    B --> C[DPI Engine]
    C --> D[Dispatcher]
    D --> E[Worker 1]
    D --> F[Worker 2]
    E --> G[Connection Tracker]
    F --> G
    G --> H[Rule Engine (Redis)]
    H --> I{Decision}
    I -->|Forward| J[Forwarded]
    I -->|Drop| K[Dropped]
```

------------------------------------------------------------------------

# 🔄 Packet Processing Lifecycle

``` mermaid
sequenceDiagram
    participant Client
    participant API as FastAPI
    participant Engine as DPI Engine
    participant Worker
    participant Redis

    Client->>API: POST /ingest
    API->>Engine: ingest_packet()
    Engine->>Worker: dispatch()
    Worker->>Worker: extract SNI / classify
    Worker->>Redis: check rules
    Redis-->>Worker: allow / block
    Worker-->>Engine: action
    Engine-->>API: response
```

------------------------------------------------------------------------

# 📂 Project Structure

    app/
    ├── main.py
    ├── schema/
    │   ├── packet_schema.py
    │   ├── connection_schema.py
    │   ├── stats_schema.py
    │   ├── rule_schema.py
    │   ├── dpi_config_schema.py
    │
    ├── services/
    │   ├── dpi_engine.py
    │   ├── dispatcher_service.py
    │   ├── connection.py
    │   ├── rule_service.py
    │
    ├── cache/
    │   └── redis.py
    │
    ├── utils/
    │   └── platform.py

------------------------------------------------------------------------

# 🔐 Flow-Based Blocking

Blocking is applied at the **connection level**.

Example:

    SYN → Allowed
    SYN-ACK → Allowed
    Client Hello → SNI detected (YouTube)
    Rule: YouTube blocked
    Flow marked BLOCKED
    All future packets → DROP

------------------------------------------------------------------------

# 🚫 Rule Engine (Redis Backed)

Rules are stored in Redis sets:

-   `blocked:ips`
-   `blocked:apps`
-   `blocked:domains`

Advantages:

-   Real-time rule updates
-   Distributed architecture support
-   Horizontal scalability

------------------------------------------------------------------------

# 📊 Statistics Tracking

Tracked metrics:

-   total_packets
-   total_bytes
-   tcp_packets
-   udp_packets
-   forwarded_packets
-   dropped_packets

Thread-safe via async locking.

------------------------------------------------------------------------

# ⚙️ Running the Service

### 1️⃣ Install Dependencies

``` bash
pip install fastapi uvicorn redis pydantic
```

### 2️⃣ Start Redis

``` bash
redis-server
```

### 3️⃣ Run Server

``` bash
uvicorn app.main:app --reload
```

------------------------------------------------------------------------

# 🧪 Example Request

``` json
POST /ingest

{
  "src_ip": "192.168.1.100",
  "dst_ip": "142.250.185.206",
  "src_port": 52345,
  "dst_port": 443,
  "protocol": "TCP",
  "size": 1200
}
```

------------------------------------------------------------------------

# 🏆 Key Engineering Highlights

-   Flow-aware DPI logic
-   TLS SNI extraction strategy
-   Async worker pool design
-   Redis distributed rule management
-   Clean microservice separation
-   Production-grade backend architecture

------------------------------------------------------------------------

# 🚀 Future Enhancements

-   Kafka-based packet ingestion
-   QUIC (HTTP/3) detection
-   Prometheus metrics integration
-   Web dashboard
-   Horizontal auto-scaling workers
-   gRPC integration with C++ core

------------------------------------------------------------------------