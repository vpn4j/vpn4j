#!/usr/bin/env bash
# Build libvpn4j_native.so from bind-mounted /src into /out.
# Expects: /src/CMakeLists.txt, writable /out
# Optional: USER_ID / GROUP_ID to chown artifacts on the host mount.
set -euo pipefail

SRC_DIR="${VPN4J_NATIVE_SRC:-/src}"
OUT_DIR="${VPN4J_NATIVE_OUT:-/out}"
BUILD_DIR="${OUT_DIR}/build"
BUILD_TESTS="${VPN4J_BUILD_TESTS:-ON}"

if [[ ! -f "${SRC_DIR}/CMakeLists.txt" ]]; then
  echo "error: ${SRC_DIR}/CMakeLists.txt not found (bind-mount vpn4j-native to /src)" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
# Drop host-path CMakeCache (bind mount) so container /src + /out stay consistent.
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

CMAKE_ARGS=(
  -S "${SRC_DIR}"
  -B "${BUILD_DIR}"
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_INSTALL_PREFIX="${OUT_DIR}"
  -DVPN4J_BUILD_TESTS="${BUILD_TESTS}"
)

# Extra cmake flags from `docker compose run ... -- -DFOO=ON`
if [[ "$#" -gt 0 ]]; then
  CMAKE_ARGS+=("$@")
fi

cmake "${CMAKE_ARGS[@]}"
cmake --build "${BUILD_DIR}" --parallel "$(nproc)"

if [[ "${BUILD_TESTS}" == "ON" ]]; then
  ctest --test-dir "${BUILD_DIR}" --output-on-failure
fi

mkdir -p "${OUT_DIR}/lib"
cp -f "${BUILD_DIR}/lib/libvpn4j_native.so" "${OUT_DIR}/lib/"

# Avoid root-owned artifacts on the host bind mount.
if [[ -n "${USER_ID:-}" && -n "${GROUP_ID:-}" ]]; then
  chown -R "${USER_ID}:${GROUP_ID}" "${OUT_DIR}" || true
fi

echo "=== Build complete ==="
ls -la "${OUT_DIR}/lib/libvpn4j_native.so"
