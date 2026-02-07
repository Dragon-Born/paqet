# paqet

A bidirectional packet-level proxy that transports encrypted tunnels (KCP, QUIC, UDP) inside raw TCP packets, bypassing DPI (Deep Packet Inspection) and restrictive firewalls.

## How paqet Bypasses DPI

paqet uses a unique approach: it runs transport protocols (KCP, QUIC, UDP) over raw TCP packets injected directly at the network driver level, completely bypassing the operating system's TCP/IP stack.

### The Core Bypass Mechanism

```
Traditional VPN Traffic (Blocked by DPI):
┌─────────────────────────────────────────────────────────┐
│  UDP/QUIC Packet (DPI fingerprints protocol headers)   │
│  ┌───────────────┬─────────────────────────────────┐   │
│  │ UDP Header    │ QUIC/WireGuard/OpenVPN Payload  │   │──► BLOCKED
│  └───────────────┴─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘

paqet Traffic (Invisible to DPI):
┌─────────────────────────────────────────────────────────┐
│  Raw TCP Packet (Looks like normal HTTPS connection)   │
│  ┌───────────────┬─────────────────────────────────┐   │
│  │ TCP Header    │ Encrypted Transport Payload     │   │──► PASSES
│  │ (PSH+ACK)     │ (KCP/QUIC/UDP inside)           │   │
│  └───────────────┴─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Why This Works Against DPI

#### 1. Raw Socket Injection (Invisible to Stateful Inspection)

paqet doesn't use the OS TCP/IP stack. Instead:

- **Packet Capture**: Uses pcap or AF_PACKET to receive packets directly from the network driver, *before* the OS firewall processes them
- **Packet Injection**: Crafts complete Ethernet/IP/TCP frames using gopacket and injects them directly to the network driver

```
Normal Application          paqet
      │                       │
      ▼                       │
┌──────────────┐              │
│ Application  │              │
├──────────────┤              │
│   TCP/IP     │              │
│   Stack      │──────────────┼───► Bypassed!
├──────────────┤              │
│  Firewall    │              │
├──────────────┤              ▼
│   Driver     │◄─────── Raw Packet I/O
└──────────────┘
      │
   Network
```

Key insight: DPI systems use stateful TCP connection tracking. Since paqet doesn't create real OS-level TCP connections, there's no connection state for DPI to track or fingerprint.

#### 2. Realistic TCP Fingerprinting

Each packet is crafted to look like legitimate TCP traffic:

| Field | Technique |
|-------|-----------|
| **TOS** | Randomized per-connection (0x00, 0x10, 0x08) |
| **TTL** | Randomized 60-68 (realistic hop counts) |
| **Sequence Numbers** | MSS-based increments (base + counter × 1460) |
| **Window Size** | Randomized 64240-65535 |
| **Timestamps** | Real elapsed time + jitter (±10ms) |
| **TSval/TSecr** | Realistic echo values with 50-250ms offset |
| **TCP Flags** | Configurable cycling (PSH+ACK, ACK, etc.) |
| **Options** | Full TCP option stack (MSS, SACK, Timestamps, Window Scale) |

This makes traffic statistically indistinguishable from normal HTTPS sessions.

#### 3. QUIC Mode: HTTP/3 Mimicry

When using QUIC transport (`protocol: "quic"`), paqet mimics legitimate HTTP/3 traffic:

- **ALPN**: Set to `h3` by default (HTTP/3 Application-Layer Protocol Negotiation)
- **TLS 1.3**: Standard QUIC-TLS handshake with ECDSA certificates
- **Deterministic Certificates**: Client and server derive identical TLS certificates from a shared key, eliminating the need for CA-signed certs while maintaining TLS security

```yaml
transport:
  protocol: "quic"
  quic:
    key: "shared-secret"    # Both sides derive same cert
    alpn: "h3"              # Advertises as HTTP/3
```

To DPI systems, this appears as a standard HTTP/3 connection to a web server.

#### 4. Why Auto Mode Can Be Faster Than Explicit QUIC

Auto mode (`protocol: "auto"`) probes multiple protocols and selects the fastest:

```
Auto Mode Protocol Selection:
1. Client probes KCP, QUIC, UDP with 3 pings each
2. Measures RTT for each protocol
3. Selects protocol with lowest latency
4. Uses that protocol for the session
```

This can outperform explicit QUIC mode because:

- **Network-Aware Selection**: Auto mode might select KCP or UDP if they perform better on your specific network path
- **ISP Behavior Variation**: Some ISPs apply different QoS policies to different traffic patterns
- **Protocol Tag Overhead**: In auto mode, a 1-byte protocol tag enables efficient server-side demuxing, which may interact differently with DPI systems

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Client                                    │
├─────────────────────────────────────────────────────────────────────┤
│  ┌────────────────┐                                                 │
│  │ SOCKS5 / TUN / │  Application Layer                              │
│  │ Port Forward   │                                                 │
│  └───────┬────────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│  ┌────────────────┐                                                 │
│  │ Protocol Layer │  Binary encoding (PTCP, PUDP, PING/PONG)        │
│  │ (gob encoding) │                                                 │
│  └───────┬────────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│  ┌────────────────┐                                                 │
│  │ Transport      │  KCP (ARQ + smux) / QUIC (TLS 1.3) / UDP        │
│  │ (tnet.Conn)    │  Stream multiplexing over single connection     │
│  └───────┬────────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│  ┌────────────────┐                                                 │
│  │ Socket Layer   │  Raw packet crafting + injection                │
│  │ (PacketConn)   │  pcap / AF_PACKET backends                      │
│  └───────┬────────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│     [ Raw TCP Packets ]──────────────►[ Internet ]                  │
└─────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           Server                                    │
├─────────────────────────────────────────────────────────────────────┤
│     [ Raw TCP Packets ]◄──────────────[ Internet ]                  │
│          │                                                          │
│          ▼                                                          │
│  ┌────────────────┐                                                 │
│  │ Socket Layer   │  BPF filter: "tcp and dst port <PORT>"          │
│  │ (PacketConn)   │  Receives packets before OS firewall            │
│  └───────┬────────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│  ┌────────────────┐                                                 │
│  │ Protocol Demux │  Auto mode: Routes by 1-byte tag                │
│  │ (multi.go)     │  0x10=KCP, 0x20=QUIC, 0x30=UDP                  │
│  └───────┬────────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│  ┌────────────────┐                                                 │
│  │ Transport      │  Decrypts and demultiplexes streams             │
│  │ (tnet.Listener)│                                                 │
│  └───────┬────────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│  ┌────────────────┐                                                 │
│  │ Protocol Layer │  Decodes requests, dials targets                │
│  │ (server/*.go)  │                                                 │
│  └───────┬────────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│     [ Target Servers ]                                              │
└─────────────────────────────────────────────────────────────────────┘
```

### Server-Side Requirements

The server must prevent the OS kernel from sending RST packets for "unexpected" TCP traffic:

```bash
# Required iptables rule on server
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

This stops the kernel from interfering with paqet's raw packet handling.

## Protocol Comparison

| Protocol | Best For | DPI Resistance | Notes |
|----------|----------|----------------|-------|
| **QUIC** | High censorship | Excellent | Mimics HTTP/3, TLS 1.3 encrypted |
| **KCP** | Lossy networks | Good | Aggressive ARQ, tunable presets |
| **UDP** | Low overhead | Moderate | Minimal encryption, fast |
| **Auto** | Unknown networks | Best | Probes and selects optimal |

## Quick Start (Iran-Optimized Configuration)

### Server (Outside Iran)

```yaml
role: "server"

network: {}  # Auto-detect

server:
  listen: ":443"  # Use standard HTTPS port

transport:
  protocol: "auto"  # Accept all protocols

  kcp:
    mode: "fast2"
    key: "your-32-byte-secret-key"

  quic:
    key: "your-32-byte-secret-key"
    alpn: "h3"  # HTTP/3 mimicry
```

### Client (Inside Iran)

```yaml
role: "client"

network: {}  # Auto-detect

socks5:
  - listen: "127.0.0.1:1080"

server:
  addr: "your-server-ip:443"

transport:
  protocol: "auto"  # Let paqet choose the best
  conn: 4           # Multiple connections for resilience

  kcp:
    mode: "fast2"
    key: "your-32-byte-secret-key"

  quic:
    key: "your-32-byte-secret-key"
    alpn: "h3"
```

## Why paqet Works in Iran

Iran's DPI system primarily targets:

1. **Known VPN protocols** (OpenVPN, WireGuard, Shadowsocks signatures)
2. **UDP traffic** (Most QUIC implementations use raw UDP)
3. **Non-standard ports** (Common VPN ports like 1194, 51820)
4. **Stateful connection anomalies** (Connections without proper TCP handshakes)

paqet evades all of these:

| DPI Check | paqet's Counter |
|-----------|-----------------|
| Protocol signature detection | Encrypted payload, no recognizable headers |
| UDP blocking | Transport runs over TCP packets |
| Port blocking | Can use port 443 (HTTPS) |
| Connection state tracking | Raw packets bypass OS stack, no trackable state |
| Traffic analysis | Randomized TCP fields, realistic fingerprints |
| TLS fingerprinting (QUIC) | Standard QUIC-TLS with `h3` ALPN |

## Building

```bash
# Standard build (requires libpcap-dev)
CGO_ENABLED=1 go build -o paqet ./cmd/

# Linux-only: Build without libpcap
CGO_ENABLED=0 GOOS=linux go build -tags nopcap -o paqet ./cmd/
```

## Running

```bash
# Requires root/sudo for raw socket access
sudo ./paqet run -c config.yaml
```

## License

[Add your license here]
