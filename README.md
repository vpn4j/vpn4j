# vpn4j

Clean-room **Java** WireGuard-compatible VPN library: same Noise/ECC crypto story as WireGuard, with **TUN** and **TCP tunnel** transport config options.

Apache-2.0 (see `LICENSE`).

## Philosophy

Same JVM/JNI contracts as [tensor4j](https://github.com/tensor4j/tensor4j):

- **C++ owns real bytes** (TUN, staging buffers); Java owns API, config, and `close()`
- **Opaque `long` handles** across JNI — no field-unpacking on hot paths
- **Fail-fast** native load — no silent Java fallback when native is required
- **Newest C++** only for native (`vpn4j-native`, C++23)
- **Clean-room** vs `.notes/wireguard-linux` — study, do not paste

See [docs/](docs/).

## Modules

| Module | Purpose |
|--------|---------|
| `vpn4j-pom` | Parent POM |
| `vpn4j` | Core Java API + protocol (clean-room) |
| `vpn4j-native` | C++23 / JNI (`libvpn4j_native.so`) — TUN and host I/O |

## Build

JDK 21+ (set `JAVA_HOME`). C++23 for native (GCC 13+ / Clang 17+).

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
cd vpn4j-pom
mvn install
```

Native library (Docker compose + bind mounts — same idea as tensor4j):

```bash
./scripts/build-native.sh
# mounts: vpn4j-native → /src:ro , vpn4j-native/target → /out
export VPN4J_NATIVE_LIBRARY=$PWD/vpn4j-native/target/lib/libvpn4j_native.so
```

Host-only cmake: `./scripts/build-native.sh --host`

## CLI

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
cd vpn4j-pom && mvn -q install -DskipTests
JAR=../vpn4j-cli/target/vpn4j-cli-1.0.0-SNAPSHOT.jar

java -jar $JAR smoke
java -jar $JAR genkey | tee priv.key | java -jar $JAR pubkey

# wg-style conf (see vpn4j-cli/examples/)
java -jar $JAR up --config peer.conf
# real TUN (root/CAP_NET_ADMIN + native lib):
export VPN4J_NATIVE_LIBRARY=$PWD/../vpn4j-native/target/lib/libvpn4j_native.so
sudo -E java -jar $JAR up --config peer.conf --tun
```

## Reference material

Local only (gitignored): `.notes/wireguard-linux` — deep clone of the native Linux WireGuard tree.
