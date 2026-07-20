# vpn4j runtimes

vpn4j has **two tracks**. They share the repo but must not blur ownership.

## Tracks

| Track | Role | Language | Packages / tree |
|-------|------|----------|-----------------|
| **protocol** | Noise_IK handshake, timers, allowed-IPs, peer state, config | Java (clean-room) | `com.github.vpn4j.protocol`, `crypto`, `config`, `device` |
| **native I/O** | TUN device, packet read/write staging, OS glue | C++23 + JNI | `vpn4j-native/`, `com.github.vpn4j.nativeapi` |

Rules:

- Protocol logic is **not** a thin wrapper over `wireguard-linux` sources.
- Native code does **not** re-implement the handshake in C++ unless a measured hot path later demands it (then still clean-room).
- TCP tunnel mode is a **transport config** next to classic UDP; both feed the same protocol track.
- Never silent-fallback from native TUN to a fake path when the library was requested.

## Transports (config)

| Mode | Meaning |
|------|---------|
| `TUN` | Classic WireGuard-style UDP under a TUN interface |
| `TCP_TUNNEL` | Same crypto/session model; outer transport is TCP tunnel |

## Crypto (protocol track)

| Primitive | Implementation |
|-----------|----------------|
| BLAKE2s / HMAC-BLAKE2s / keyed MAC | Pure Java (`Blake2s`, `Hkdf`) — RFC 7693 |
| X25519 | JDK `KeyAgreement` / `XEC*` (`X25519`) |
| ChaCha20-Poly1305 | JDK `Cipher` (`ChaCha20Poly1305`) |
| Noise_IKpsk2 handshake | `NoiseHandshake` (public WireGuard protocol) |
| Transport data + replay | `DataPacket`, `TransportSession`, `ReplayWindow` |
| Outer carrier | `UdpCarrier` (`TUN` mode), `TcpTunnelCarrier` (`TCP_TUNNEL`, length-prefixed) |
| Peer engine | `PeerEngine` — handshake + TUN↔data + keepalive/rekey tick |
| Device engine | `DeviceEngine` — multi-peer demux; `AllowedIpsTable` LPM (v4/v6) |
| Cookies | `CookieChecker` + XChaCha20-Poly1305; `PeerEngine.setUnderLoad(true)` |
| Config | `WgConfigParser` — WireGuard-style `[Interface]` / `[Peer]` |

## Test strategy

1. Pure Java protocol/crypto unit tests (no `.so`) — RFC Blake2s vectors + handshake key agreement.
2. Native GoogleTest for TUN/handle lifetime.
3. JNI bridge tests with `VPN4J_NATIVE_LIBRARY` set (fail-fast if missing when profile requires native).
