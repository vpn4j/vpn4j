# Memory — ownership and domains

## Who owns what

**C++ owns the real bytes** for TUN and staging. Java owns API, config, budgets, metrics, and `close()`. JNI passes handles only.

| Layer | Owner |
|-------|-------|
| TUN fd / OS interface | C++ `vpn4j::tun` |
| Packet staging buffers | C++ pools/arenas |
| Session keys / replay counters | Java protocol track (initially); may move hot paths later |
| `Device` / `Peer` / config | Java |
| Cleaner / GC | Safety net only |
| `DirectByteBuffer` | Not the owner of TUN-backed packets |

## Domains

1. Java heap — config, peer metadata, strings (never bulk packet payloads as the primary path)
2. Host off-heap — C++ staging
3. Kernel TUN — OS

Silent copies across domains without a named API are bugs.
