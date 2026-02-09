# Network Discovery Report

**Target:** `192.168.145.129`
**Source Host:** `kali`
**Run Started:** 2026-02-09T17:46:10.949838Z

## Host Reachability
- ICMP Echo: **Not Reachable**

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
  "target": "192.168.145.129",
  "evidence": {
    "method": "icmp_echo_ping",
    "reachable": false,
    "timeout_s": 1
  },
  "confidence": 0.6,
  "observed_at": "2026-02-09T17:46:11.954523Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "192.168.145.129:53",
  "evidence": {
    "method": "tcp_connect",
    "port": 53,
    "service_hint": "DNS",
    "timeout_s": 1.0,
    "error": "OSError"
  },
  "confidence": 0.5,
  "observed_at": "2026-02-09T17:46:14.009812Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "192.168.145.129:139",
  "evidence": {
    "method": "tcp_connect",
    "port": 139,
    "service_hint": "SMB",
    "timeout_s": 1.0,
    "error": "OSError"
  },
  "confidence": 0.5,
  "observed_at": "2026-02-09T17:46:17.077920Z"
}
```

```json
{
  "domain": "network",
  "category": "port_probe_error",
  "target": "192.168.145.129:3389",
  "evidence": {
    "method": "tcp_connect",
    "port": 3389,
    "service_hint": "RDP",
    "timeout_s": 1.0,
    "error": "OSError"
  },
  "confidence": 0.5,
  "observed_at": "2026-02-09T17:46:20.149786Z"
}
```
