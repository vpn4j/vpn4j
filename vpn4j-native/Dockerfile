# Reproducible native toolchain for vpn4j JNI builds (C++23 + JDK 21).
# Bind mounts (no COPY of sources):
#   /src  -> vpn4j-native (read-only)
#   /out  -> build products (libvpn4j_native.so)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    g++ \
    make \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
WORKDIR /out

COPY docker-build.sh /usr/local/bin/vpn4j-native-build
RUN chmod +x /usr/local/bin/vpn4j-native-build

RUN cmake --version && g++ --version && java -version

ENTRYPOINT ["/usr/local/bin/vpn4j-native-build"]
