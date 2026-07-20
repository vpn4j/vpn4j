package com.github.vpn4j.config;

import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.Keys;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Parsed WireGuard-style configuration.
 */
public final class WgConfig {

    private final KeyPair identity;
    private final int listenPort;
    private final String interfaceName;
    private final List<String> addresses;
    private final List<PeerConfig> peers;

    private WgConfig(Builder b) {
        this.identity = b.identity;
        this.listenPort = b.listenPort;
        this.interfaceName = b.interfaceName;
        this.addresses = Collections.unmodifiableList(new ArrayList<>(b.addresses));
        this.peers = Collections.unmodifiableList(new ArrayList<>(b.peers));
    }

    public KeyPair identity() {
        return identity;
    }

    public int listenPort() {
        return listenPort;
    }

    public String interfaceName() {
        return interfaceName;
    }

    public List<String> addresses() {
        return addresses;
    }

    public List<PeerConfig> peers() {
        return peers;
    }

    public DeviceConfig toDeviceConfig(TransportMode mode) {
        DeviceConfig.Builder b = DeviceConfig.builder()
                .transportMode(mode == null ? TransportMode.TUN : mode)
                .interfaceName(interfaceName)
                .listenPort(listenPort);
        return b.build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private KeyPair identity;
        private int listenPort = 51820;
        private String interfaceName = "vpn4j0";
        private final List<String> addresses = new ArrayList<>();
        private final List<PeerConfig> peers = new ArrayList<>();

        public Builder privateKey(Key privateKey) {
            this.identity = Keys.keyPairFromPrivate(privateKey);
            return this;
        }

        public Builder privateKeyBase64(String base64) {
            return privateKey(Keys.fromBase64(base64));
        }

        public Builder listenPort(int listenPort) {
            this.listenPort = listenPort;
            return this;
        }

        public Builder interfaceName(String interfaceName) {
            this.interfaceName = interfaceName;
            return this;
        }

        public Builder addAddress(String cidr) {
            this.addresses.add(cidr);
            return this;
        }

        public Builder addPeer(PeerConfig peer) {
            this.peers.add(peer);
            return this;
        }

        public WgConfig build() {
            if (identity == null) {
                throw new IllegalArgumentException("Interface PrivateKey required");
            }
            if (listenPort < 0 || listenPort > 65535) {
                throw new IllegalArgumentException("ListenPort out of range");
            }
            return new WgConfig(this);
        }
    }

    public static PeerConfig.Builder peerBuilder(Key publicKey) {
        return PeerConfig.builder(publicKey);
    }

    public static InetSocketAddress parseEndpoint(String endpoint) {
        if (endpoint == null || endpoint.isEmpty()) {
            return null;
        }
        String s = endpoint.trim();
        if (s.startsWith("[")) {
            int end = s.indexOf(']');
            if (end < 0 || end + 1 >= s.length() || s.charAt(end + 1) != ':') {
                throw new IllegalArgumentException("bad IPv6 endpoint: " + endpoint);
            }
            String host = s.substring(1, end);
            int port = Integer.parseInt(s.substring(end + 2));
            return new InetSocketAddress(host, port);
        }
        int colon = s.lastIndexOf(':');
        if (colon <= 0) {
            throw new IllegalArgumentException("bad endpoint: " + endpoint);
        }
        return new InetSocketAddress(s.substring(0, colon), Integer.parseInt(s.substring(colon + 1)));
    }
}
