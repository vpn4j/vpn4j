# vpn4j-native

C++23 / JNI library for TUN and host I/O (`libvpn4j_native.so`).

## Ownership

C++ owns TUN fd and staging. Java holds opaque `long` handles across JNI.

## Build (Docker — source of truth)

Bind mounts: `vpn4j-native` → `/src:ro`, `vpn4j-native/target` → `/out`.
Artifacts are `chown`'d to the host user via `USER_ID` / `GROUP_ID`.

```bash
# Preferred
bash scripts/build-native.sh

# Or direct compose
mkdir -p vpn4j-native/target
USER_ID=$(id -u) GROUP_ID=$(id -g) \
  docker compose -f vpn4j-native/docker-compose.yml run --rm vpn4j-native
```

Produces: `vpn4j-native/target/lib/libvpn4j_native.so`

```bash
export VPN4J_NATIVE_LIBRARY=$PWD/vpn4j-native/target/lib/libvpn4j_native.so
```

Force image rebuild: `bash scripts/build-native.sh --rebuild`

Host cmake (no Docker): `bash scripts/build-native.sh --host`

## Layout

```
Dockerfile          toolchain image (Ubuntu 24.04, JDK 21, g++ C++23)
docker-compose.yml  /src:ro + /out bind mounts
docker-build.sh     container entrypoint
include/            C++ headers (vpn4j/*.hpp)
src/                TUN + JNI
tests/              GoogleTest
```
