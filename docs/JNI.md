# JNI contracts — vpn4j

Aligned with tensor4j [JNI vs OpenJDK](https://github.com/tensor4j/tensor4j/blob/main/docs/JNI_VS_OPENJDK.md) and JEP 454 direction.

## Rules

1. **Opaque `long` handle** → native object (`vpn4j::TunDevice*`, etc.). Do not unpack Java objects field-by-field on the hot path.
2. **Bulk ops** — one JNI entry per read/write batch where possible; keep buffers in C++ between calls.
3. **No `GetPrimitiveArrayCritical` on I/O/crypto hot paths** — copy into memory we own, or use direct buffers we allocated natively.
4. **Typed errors** — `vpn4j::Status` → Java exceptions (`TunRequired`, `NativeLoadFailed`, config errors).
5. **Cleaner = safety net only** — primary free path is `close()` / try-with-resources.
6. **`RegisterNatives` / schema** as the surface grows — avoid hand-drifted `Java_*` name rot.
7. **`nativeBridge=JNI|PANAMA|AUTO` later** — same Java device API.
8. **C++23 only** under `vpn4j-native/` — no other native languages.

## Load policy

| Variable / property | Meaning |
|---------------------|---------|
| `VPN4J_NATIVE_LIBRARY` | Absolute path to `libvpn4j_native.so` |
| `vpn4j.native.library` | Same, as system property |

**Fail-fast:** when TUN/native is required, missing library → `UnsatisfiedLinkError` / typed load failure. No silent stub device.
