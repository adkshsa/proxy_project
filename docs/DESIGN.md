# Design Document: Custom Network Proxy Server

## 1. High-Level Architecture
The system is designed as a modular forward proxy server. It consists of four core components:
- **Authentication Manager**: Validates users via Basic Access Authentication.
- **Site Filter**: A rule-based engine that matches requested hosts against a blacklist.
- **Cache Manager**: An LRU-based storage system for HTTP GET responses.
- **Logger**: A thread-safe utility for recording server events and traffic metrics.



## 2. Concurrency Model
We implemented a **Thread-per-Connection** model using `std::thread`. 
- **Rationale**: This approach is robust and provides a dedicated execution context for each client. Since proxy operations involve blocking I/O (waiting for remote servers), threads allow the server to remain responsive to other clients without the complexity of an asynchronous event loop.

## 3. Data Flow
1. **Ingress**: The server accepts a TCP connection and accumulates the HTTP header.
2. **Auth & Filter**: The request is parsed. If authentication fails or the host is in `blocked.txt`, a `407` or `403` response is sent immediately.
3. **Cache Lookup**: For `GET` requests, the server checks the LRU cache. If a hit occurs, the data is served from memory.
4. **Relay/Tunnel**: 
    - For **HTTP**: The server connects to the target and forwards the request.
    - For **HTTPS**: The server uses the `CONNECT` method to establish a transparent TCP tunnel.
5. **Egress**: Data is streamed back to the client using a bidirectional `select()` loop.

## 4. Caching Strategy & Performance
To optimize throughput, we implemented an **LRU (Least Recently Used) Cache**.
- **Mechanism**: The cache uses a `std::unordered_map` for $O(1)$ lookup and a `std::list` to track usage frequency and handle evictions.
- **Observation**: Stress testing showed a significant increase in requests per second. Serving repeated requests from memory reduces outbound network latency and CPU overhead.



## 5. Security & Error Handling
- **Authentication**: Prevents "Open Proxy" exploitation.
- **Robustness**: The server handles partial reads and uses `select()` to avoid hanging on dead sockets.
- **Filtering**: Uses canonicalization (lowercase/trimming) and suffix matching to prevent bypasses (e.g., `www.facebook.com` vs `facebook.com`).