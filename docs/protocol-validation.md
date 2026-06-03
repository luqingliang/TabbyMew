# Protocol Validation

This document tracks protocol interoperability coverage for release hardening.

Current status: only Trojan has accepted real-server validation records. All
other implemented outbound protocols are covered by engineering tests only until
their real-server runs are manually re-executed and recorded here.

## Automated Coverage

The CI test suite uses local mock peers and local process integration tests so
protocol regressions stay deterministic. This is engineering coverage, not
accepted real-server validation:

| Protocol | TCP | UDP | Coverage |
| --- | --- | --- | --- |
| Trojan | Yes | Yes | Engineering tests plus accepted real-server validation records below |
| Shadowsocks | Yes | Yes | `aes-128-gcm` client/server stream and UDP packet round trips |
| Shadowsocks 2022 | Yes | Yes | `2022-blake3-aes-128-gcm` client/server stream and UDP packet round trips |
| AnyTLS | Yes | Yes | Frame encoding, session reuse, dynamic padding-scheme updates, and UoT v2 UDP tests |

Integration tests that start local proxy processes are run with one test thread.
This avoids port and child-process contention while keeping the tests independent
from public servers.

The real-server suites are intentionally ignored by default because they require
external proxy binaries and localhost socket permissions:

```bash
./scripts/interop-sing-box.sh
./scripts/interop-xray.sh
./scripts/interop-v2ray.sh
```

## Manual Interop Checklist

Before a tagged release, run these against real implementations such as sing-box,
Xray, v2ray-core, or a Shadowsocks server:

1. Trojan over TLS, TCP and UDP relay, including large UDP payload rejection behavior.
2. Shadowsocks `aes-128-gcm` TCP and UDP.
3. Shadowsocks 2022 `2022-blake3-aes-128-gcm` TCP and UDP.
4. AnyTLS TCP and UDP using sing-box UoT v2, including idle session reuse and server padding-scheme update handling.
5. Hybrid routing where TCP and UDP for the same domain resolve through configured DNS and route to different outbounds.

Record server implementation, version, method/security, transport, and result for
each run. Public endpoints and secrets should not be committed.

## Accepted Real-Server Validation Record

Only rows in this table count as current real-server validation. Non-Trojan
protocols must remain classified as engineering-tested until a fresh manual
real-server run is recorded here.

| Date | Implementation | Version | Protocol | Method/security | TCP | UDP | Destination coverage | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-05-23 | sing-box | 1.13.12 | Trojan | TLS password auth | Pass | Pass | domain address type, IPv4, IPv6 | Localhost interop via `scripts/interop-sing-box.sh` |
| 2026-05-23 | Xray | 26.3.27 | Trojan | TLS password auth | Pass | Pass | domain address type, IPv4, IPv6 | Localhost interop via `scripts/interop-xray.sh` |
| 2026-05-23 | v2ray-core | 5.49.0 | Trojan | TLS password auth | Pass | Pass | domain address type, IPv4, IPv6 | Localhost interop via `scripts/interop-v2ray.sh` |
