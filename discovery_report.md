# Network Discovery Report

**Target:** `127.0.0.1`
**Source Host:** `kali`
**Run Started:** 2026-03-24T15:17:19.701637Z

## Host Reachability
- ICMP Echo: **Reachable**

## Exposed Services
- No externally reachable services observed

## Analyst Notes
- No network services were observed as externally reachable during this run.
- This may indicate a hardened firewall posture or disabled services.

## Appendix: Raw Findings
```json
{
  "domain": "network",
  "category": "host_presence",
  "target": "127.0.0.1",
  "evidence": {
    "method": "icmp_echo_ping",
    "reachable": true,
    "timeout_s": 1
  },
  "confidence": 0.9,
  "observed_at": "2026-03-24T15:17:19.703271Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:21",
  "evidence": {
    "method": "tcp_connect",
    "port": 21,
    "service_hint": "FTP",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704037Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:22",
  "evidence": {
    "method": "tcp_connect",
    "port": 22,
    "service_hint": "SSH",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704071Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:53",
  "evidence": {
    "method": "tcp_connect",
    "port": 53,
    "service_hint": "DNS",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704096Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:80",
  "evidence": {
    "method": "tcp_connect",
    "port": 80,
    "service_hint": "HTTP",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704119Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:88",
  "evidence": {
    "method": "tcp_connect",
    "port": 88,
    "service_hint": "Kerberos",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704142Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:135",
  "evidence": {
    "method": "tcp_connect",
    "port": 135,
    "service_hint": "RPC",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704164Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:139",
  "evidence": {
    "method": "tcp_connect",
    "port": 139,
    "service_hint": "SMB",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704185Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:389",
  "evidence": {
    "method": "tcp_connect",
    "port": 389,
    "service_hint": "LDAP",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704210Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:443",
  "evidence": {
    "method": "tcp_connect",
    "port": 443,
    "service_hint": "HTTPS",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704231Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:445",
  "evidence": {
    "method": "tcp_connect",
    "port": 445,
    "service_hint": "SMB",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704250Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:3389",
  "evidence": {
    "method": "tcp_connect",
    "port": 3389,
    "service_hint": "RDP",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704271Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:5985",
  "evidence": {
    "method": "tcp_connect",
    "port": 5985,
    "service_hint": "WinRM",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704290Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "127.0.0.1:5986",
  "evidence": {
    "method": "tcp_connect",
    "port": 5986,
    "service_hint": "WinRM-HTTPS",
    "timeout_s": 1.0,
    "error": "ConnectionRefusedError"
  },
  "confidence": 0.5,
  "observed_at": "2026-03-24T15:17:19.704309Z"
}
```
