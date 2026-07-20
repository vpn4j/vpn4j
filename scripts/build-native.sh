#!/usr/bin/env bash
# Build libvpn4j_native.so via docker compose with bind-mounted /src and /out
# (tensor4j-style). Host cmake path: ./scripts/build-native.sh --host
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="$ROOT/vpn4j-native/docker-compose.yml"
OUT="${VPN4J_NATIVE_OUT:-$ROOT/vpn4j-native/target}"
DEFAULT_OUT="$ROOT/vpn4j-native/target"

HOST_BUILD=false
REBUILD=false
CMAKE_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --host) HOST_BUILD=true ;;
    --rebuild) REBUILD=true ;;
    *) CMAKE_ARGS+=("$arg") ;;
  esac
done

build_host() {
  NATIVE="$ROOT/vpn4j-native"
  BUILD="$NATIVE/target/build"
  OUT_LIB="$NATIVE/target/lib"

  if [[ -z "${JAVA_HOME:-}" ]]; then
    if [[ -d /usr/lib/jvm/java-21-openjdk-amd64 ]]; then
      export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
    elif [[ -d /usr/lib/jvm/java-21-openjdk ]]; then
      export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
    else
      echo "JAVA_HOME is not set" >&2
      exit 1
    fi
  fi

  mkdir -p "$BUILD" "$OUT_LIB"
  cmake -S "$NATIVE" -B "$BUILD" -DVPN4J_BUILD_TESTS=ON "${CMAKE_ARGS[@]+"${CMAKE_ARGS[@]}"}"
  cmake --build "$BUILD" --parallel
  mkdir -p "$OUT_LIB"
  cp -f "$BUILD/lib/libvpn4j_native.so" "$OUT_LIB/"
  ctest --test-dir "$BUILD" --output-on-failure
  echo "Built $OUT_LIB/libvpn4j_native.so"
  echo "export VPN4J_NATIVE_LIBRARY=$OUT_LIB/libvpn4j_native.so"
}

build_docker() {
  export USER_ID="${USER_ID:-$(id -u)}"
  export GROUP_ID="${GROUP_ID:-$(id -g)}"
  export VPN4J_NATIVE_IMAGE="${VPN4J_NATIVE_IMAGE:-vpn4j-native:jdk21}"
  export VPN4J_BUILD_TESTS="${VPN4J_BUILD_TESTS:-ON}"

  mkdir -p "$DEFAULT_OUT"

  if [[ "$(cd "$OUT" && pwd)" != "$(cd "$DEFAULT_OUT" && pwd)" ]]; then
    echo "ERROR: VPN4J_NATIVE_OUT must be $DEFAULT_OUT (compose bind mount)." >&2
    echo "       Got: $OUT" >&2
    exit 2
  fi

  echo "==> docker compose build/run vpn4j-native (src→/src:ro, out→/out)"
  echo "    image=$VPN4J_NATIVE_IMAGE USER_ID=$USER_ID GROUP_ID=$GROUP_ID"

  if $REBUILD; then
    docker compose -f "$COMPOSE_FILE" build --no-cache vpn4j-native
  else
    docker compose -f "$COMPOSE_FILE" build vpn4j-native
  fi

  docker compose -f "$COMPOSE_FILE" run --rm --no-deps vpn4j-native \
    "${CMAKE_ARGS[@]+"${CMAKE_ARGS[@]}"}"

  SO="$OUT/lib/libvpn4j_native.so"
  if [[ ! -f "$SO" ]]; then
    echo "ERROR: libvpn4j_native.so not found under $OUT/lib" >&2
    find "$OUT" -type f | head -n 80 >&2 || true
    exit 1
  fi

  echo "==> Built: $SO"
  ls -la "$SO"
  echo "export VPN4J_NATIVE_LIBRARY=$SO"
}

if $HOST_BUILD; then
  build_host
else
  build_docker
fi
