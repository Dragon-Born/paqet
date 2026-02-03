# Iran Censorship Bypass - Research & Implementation Plan

**Date:** 2026-02-03
**Status:** Research complete, implementation pending

## Table of Contents
1. [Problem Statement](#problem-statement)
2. [Diagnosis & Findings](#diagnosis--findings)
3. [Bypass Strategies Explored](#bypass-strategies-explored)
4. [Chosen Solution](#chosen-solution)
5. [Implementation Plan](#implementation-plan)

---

## Problem Statement

paqet works on fiber/home networks but fails on Iranian cellular (IRMCI) with all protocol probes failing:

```
2026-02-03 14:06:59.528 [INFO] Starting client...
2026-02-03 14:06:59.529 [INFO] probing protocol: kcp
2026-02-03 14:07:04.566 [INFO]   kcp: failed (all pings failed)
2026-02-03 14:07:04.566 [INFO] probing protocol: quic
2026-02-03 14:07:09.587 [INFO]   quic: failed (dial timed out)
2026-02-03 14:07:09.587 [INFO] probing protocol: udp
2026-02-03 14:07:14.615 [INFO]   udp: failed (all pings failed)
2026-02-03 14:07:14.616 [FATAL] Client encountered an error: all protocol probes failed
```

---

## Diagnosis & Findings

### 1. Packet Capture Analysis

Captured 48 packets - ALL outbound, ZERO responses from server:

```
14:13:06.715391 IP 10.10.10.184.35752 > 91.107.180.174.8443: Flags [P.], seq ... length 53
14:13:06.715434 IP 10.10.10.184.35752 > 91.107.180.174.8443: Flags [P.], seq ... length 78
... (all outbound, no inbound)
```

**Finding:** Packets leave the device but responses never arrive.

### 2. Stateful Packet Inspection

paqet uses raw TCP packet injection with PSH+ACK flags but no real TCP handshake (SYN → SYN-ACK → ACK). The ISP's stateful firewall drops packets that don't belong to established connections.

### 3. Pattern-Based Throttling

Even ICMP ping gets blocked after 2-3 packets:

```bash
➜ ping 91.107.180.174
64 bytes from 91.107.180.174: icmp_seq=0 ttl=46 time=85.485 ms
64 bytes from 91.107.180.174: icmp_seq=1 ttl=46 time=90.581 ms
64 bytes from 91.107.180.174: icmp_seq=2 ttl=46 time=91.433 ms
Request timeout for icmp_seq 3
Request timeout for icmp_seq 4
...
```

**Finding:** DPI detects regular packet intervals and throttles after pattern detected.

### 4. IP Reputation System

Tested connectivity to different destinations:

| Destination | Result |
|-------------|--------|
| 8.8.8.8 (Google DNS) | 10/10 packets ✓ |
| 1.1.1.1 (Cloudflare) | 8/8 packets ✓ |
| google.com HTTPS | Works ✓ |
| 91.107.180.174 (our server) | Throttled after 2-3 packets ✗ |

**Finding:** Trusted IPs (Google, Cloudflare) work fine. Unknown IPs get throttled.

### 5. DNS Hijacking

```bash
➜ ping premiere-vernon-mortality-opt.trycloudflare.com
PING premiere-vernon-mortality-opt.trycloudflare.com (10.10.34.36): 56 data bytes
                                                       ↑
                                               FAKE private IP!
```

ISP intercepts DNS and returns fake IPs for tunnel domains.

### 6. DoH/DoT Blocked

DNS-over-HTTPS is blocked:
```bash
➜ curl -s "https://cloudflare-dns.com/dns-query?..."
(empty response)
```

### 7. Direct IP + SNI Works

Bypassing DNS with hardcoded Cloudflare IPs:
```bash
➜ curl -v --resolve "premiere-vernon-mortality-opt.trycloudflare.com:443:104.16.0.1" \
    https://premiere-vernon-mortality-opt.trycloudflare.com
* SSL connection using TLSv1.3 / AEAD-AES256-GCM-SHA384
* Server certificate: CN=trycloudflare.com ... SSL certificate verify ok.
(TLS handshake succeeds!)
```

**Key Finding:** Direct connection to Cloudflare IPs with correct SNI works!

---

## Iranian DPI Layers Identified

| Layer | Technique | What It Catches |
|-------|-----------|-----------------|
| 1 | Stateful Inspection | Raw packets without TCP handshake |
| 2 | Protocol Fingerprinting | KCP/QUIC/Shadowsocks signatures |
| 3 | Pattern Detection | Regular timing intervals |
| 4 | IP Reputation | Unknown IPs get throttled |
| 5 | DNS Hijacking | Tunnel domains return fake IPs |
| 6 | DoH/DoT Blocking | Encrypted DNS blocked |

---

## Bypass Strategies Explored

### Strategy 1: Timing Jitter (Partial Success)
Adding random delays between packets. Only marginally better - still gets blocked.

### Strategy 2: CDN Fronting via Cloudflare
Route traffic through Cloudflare's trusted IPs. **This works!**

### Strategy 3: DNS Bypass via /etc/hosts
Hardcode real Cloudflare IPs to bypass DNS hijacking. **Works!**

### Strategy 4: WebSocket over TLS
Use real TCP (not raw packets) with TLS encryption. Looks like normal HTTPS.

### Strategy 5: Cloudflare Tunnel
Use Cloudflare's tunnel service - traffic goes to trusted Cloudflare IPs.

### Strategies Considered But Not Tested

- **DNS Tunneling** - Encode data in DNS queries (slow but reliable)
- **ICMP Tunneling** - Use the 2-3 packets that get through (very slow)
- **Reverse Tunnel** - Server initiates connection to client
- **Asymmetric Protocol** - Different protocols for inbound/outbound
- **uTLS Browser Mimicry** - Clone Chrome/Firefox TLS fingerprint
- **Trojan Protocol** - Server serves real website to probes
- **Reality/XTLS** - Steal TLS sessions from real sites

---

## Chosen Solution

### Cloudflare Tunnel Integration in paqet

Embed Cloudflare tunnel client directly into paqet with:
- Hardcoded Cloudflare IPs (bypass DNS hijacking)
- WebSocket over TLS (passes stateful inspection)
- Traffic routes through trusted Cloudflare IPs (passes IP reputation)

---

## Implementation Plan

### Phase 1: Add TCP Transport (Server Side)

paqet server needs to accept normal TCP connections from cloudflared.

**New file:** `internal/tnet/tcp/listen.go`

```go
package tcp

import (
    "net"
    "github.com/xtaci/smux"
)

type Listener struct {
    listener net.Listener
    smuxCfg  *smux.Config
}

func NewListener(addr string) (*Listener, error) {
    l, err := net.Listen("tcp", addr)
    if err != nil {
        return nil, err
    }
    return &Listener{
        listener: l,
        smuxCfg:  smux.DefaultConfig(),
    }, nil
}

func (l *Listener) Accept() (tnet.Conn, error) {
    conn, err := l.listener.Accept()
    if err != nil {
        return nil, err
    }
    // Wrap with smux for stream multiplexing
    session, err := smux.Server(conn, l.smuxCfg)
    if err != nil {
        return nil, err
    }
    return &TCPConn{session: session, raw: conn}, nil
}
```

**Config:**
```yaml
# server.yaml
transport:
  protocol: tcp  # Real TCP listener
server:
  addr: ":8443"
```

### Phase 2: Add Cloudflare Transport (Client Side)

**New file:** `internal/tnet/cloudflare/conn.go`

```go
package cloudflare

import (
    "crypto/tls"
    "net"
    "github.com/gorilla/websocket"
)

type Config struct {
    Hostname string   `yaml:"hostname"`
    IPs      []string `yaml:"ips"`      // Hardcoded Cloudflare IPs
    UTLS     string   `yaml:"utls"`     // Optional: chrome, firefox
    Jitter   [2]int   `yaml:"jitter"`   // Anti-pattern: [min, max] ms
    Padding  [2]int   `yaml:"padding"`  // Anti-pattern: [min, max] bytes
}

type Transport struct {
    cfg Config
}

func (t *Transport) Dial() (net.Conn, error) {
    // 1. Pick random Cloudflare IP (bypass DNS)
    ip := t.cfg.IPs[rand.Intn(len(t.cfg.IPs))]

    // 2. Dial TCP to hardcoded IP
    tcpConn, err := net.Dial("tcp", ip+":443")
    if err != nil {
        return nil, err
    }

    // 3. TLS handshake with correct SNI
    tlsConfig := &tls.Config{
        ServerName: t.cfg.Hostname,
    }
    tlsConn := tls.Client(tcpConn, tlsConfig)
    if err := tlsConn.Handshake(); err != nil {
        return nil, err
    }

    // 4. Upgrade to WebSocket
    dialer := websocket.Dialer{
        NetDial: func(network, addr string) (net.Conn, error) {
            return tlsConn, nil
        },
    }
    wsConn, _, err := dialer.Dial("wss://"+t.cfg.Hostname+"/", nil)
    if err != nil {
        return nil, err
    }

    // 5. Wrap WebSocket as net.Conn
    return NewWSConn(wsConn), nil
}
```

**Config:**
```yaml
# client.yaml
transport:
  protocol: cloudflare
  cloudflare:
    hostname: "xxx.trycloudflare.com"
    ips:
      - "104.16.0.1"
      - "104.16.1.1"
      - "104.16.2.1"
      - "104.16.3.1"
    # Optional anti-DPI features
    utls: chrome        # Mimic browser TLS fingerprint
    jitter: [10, 100]   # Random delay before send (ms)
    padding: [0, 50]    # Random padding bytes
```

### Phase 3: Update Transport Factory

**File:** `internal/transport/factory.go`

```go
func NewTransport(cfg *conf.TransportConfig) (Transport, error) {
    switch cfg.Protocol {
    case "kcp":
        return kcp.NewTransport(cfg.KCP)
    case "quic":
        return quic.NewTransport(cfg.QUIC)
    case "udp":
        return udp.NewTransport(cfg.UDP)
    case "tcp":  // NEW
        return tcp.NewTransport(cfg.TCP)
    case "cloudflare":  // NEW
        return cloudflare.NewTransport(cfg.Cloudflare)
    default:
        return nil, fmt.Errorf("unknown protocol: %s", cfg.Protocol)
    }
}
```

### Phase 4: Optional Enhancements

#### A. uTLS Browser Mimicry
```go
import "github.com/refraction-networking/utls"

// Instead of crypto/tls
conn := utls.UClient(tcpConn, &utls.Config{
    ServerName: hostname,
}, utls.HelloChrome_Auto)
```

#### B. Anti-Pattern Layer
```go
type AntiPatternConn struct {
    inner   net.Conn
    jitter  [2]time.Duration
    padding [2]int
}

func (c *AntiPatternConn) Write(p []byte) (int, error) {
    // Random delay
    delay := c.jitter[0] + time.Duration(rand.Int63n(int64(c.jitter[1]-c.jitter[0])))
    time.Sleep(delay)

    // Random padding
    padLen := c.padding[0] + rand.Intn(c.padding[1]-c.padding[0])
    buf := make([]byte, 2+len(p)+padLen)
    binary.BigEndian.PutUint16(buf[0:2], uint16(len(p)))
    copy(buf[2:], p)
    rand.Read(buf[2+len(p):])

    return c.inner.Write(buf)
}
```

#### C. Connection Rotation
```go
type RotatingTransport struct {
    cfg        Config
    currentAge time.Duration
    maxAge     time.Duration  // Reconnect every 15-30s
}

func (t *RotatingTransport) GetConn() (net.Conn, error) {
    if t.currentAge > t.maxAge {
        t.reconnect()
    }
    return t.conn, nil
}
```

---

## Deployment Steps

### Server Setup

1. Keep cloudflared running:
   ```bash
   ./cloudflared tunnel --url tcp://localhost:8443
   ```

2. Update paqet server config:
   ```yaml
   transport:
     protocol: tcp
   server:
     addr: ":8443"
   ```

3. Run paqet server:
   ```bash
   sudo ./paqet run -c server.yaml
   ```

### Client Setup

1. Get tunnel hostname from cloudflared output

2. Add to /etc/hosts (bypass DNS hijacking):
   ```
   104.16.0.1 xxx.trycloudflare.com
   ```

3. Configure paqet client:
   ```yaml
   transport:
     protocol: cloudflare
     cloudflare:
       hostname: "xxx.trycloudflare.com"
       ips:
         - "104.16.0.1"
         - "104.16.1.1"
   ```

4. Run paqet client:
   ```bash
   sudo ./paqet run -c client.yaml
   ```

---

## Testing Checklist

- [ ] TCP listener accepts connections from cloudflared
- [ ] Cloudflare transport connects via WebSocket
- [ ] DNS bypass with hardcoded IPs works
- [ ] TLS handshake succeeds
- [ ] Data flows bidirectionally through tunnel
- [ ] SOCKS5 proxy works through tunnel
- [ ] TUN mode works through tunnel
- [ ] Connection survives for extended periods
- [ ] Anti-pattern features reduce detection

---

## Cloudflare IPs Reference

Common Cloudflare anycast IPs (for DNS bypass):

```
104.16.0.1
104.16.1.1
104.16.2.1
104.16.3.1
104.16.4.1
104.16.5.1
```

Full list: https://www.cloudflare.com/ips/

---

## Future Considerations

1. **Permanent Tunnel** - Set up named Cloudflare tunnel with token (more stable than quick tunnels)

2. **Multiple Tunnel Endpoints** - Load balance across multiple tunnels

3. **Trojan-style Fallback** - Server serves real website to probes

4. **ESNI/ECH Support** - Encrypt SNI to hide tunnel hostname

5. **Embed cloudflared server-side** - Eliminate separate cloudflared process

---

## Related Resources

- Cloudflare Tunnel docs: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps
- uTLS library: https://github.com/refraction-networking/utls
- Xray-core (Reality protocol): https://github.com/XTLS/Xray-core
