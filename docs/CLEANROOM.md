# Clean-room WireGuard port

`.notes/wireguard-linux` (gitignored deep clone) is an **oracle and autopsy subject**. Study patterns, constants, and failure modes; **do not paste** upstream C into vpn4j.

## Legal

WireGuard is GPL-2.0 in the Linux tree. vpn4j is Apache-2.0 clean-room:

- Read, note, re-implement under our API + NOTICE
- Never merge verbatim `drivers/net/wireguard/*` sources
- Protocol compatibility (Noise_IK, same AEAD/ECC algorithms) is intentional; copyrighted expression is not copied

## Study corpus

| Tree | Surfaces |
|------|----------|
| `drivers/net/wireguard/` | messages, noise, cookie, timers, allowedips, device, peer |
| WireGuard whitepaper / protocol docs | handshake, transport, data keys |

## Pin SHA

| Repo | Path | Notes |
|------|------|-------|
| WireGuard/wireguard-linux | `.notes/wireguard-linux` | Tip at clone: `78ef59e7a645` (`wireguard-fixes-for-7-1-rc6`) |

Study surfaces used so far: `drivers/net/wireguard/messages.h` (lengths/types as oracle only).

## Decision template (per subsystem)

1. Behavior / constants / edge cases
2. Decision: **Reimplement in Java** / **Native C++ (TUN/I/O only)** / **Defer**
3. Interop test plan (wg ↔ vpn4j)
