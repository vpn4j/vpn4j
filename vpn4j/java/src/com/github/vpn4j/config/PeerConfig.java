package com.github.vpn4j.config;

import com.github.vpn4j.crypto.Key;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Peer configuration: remote public key, endpoint, allowed IPs, keepalive.
 */
public final class PeerConfig {

    private final Key publicKey;
    private final Key presharedKey;
    private final InetSocketAddress endpoint;
    private final List<String> allowedIps;
    private final int persistentKeepaliveSeconds;

    private PeerConfig(Builder builder) {
        this.publicKey = builder.publicKey;
        this.presharedKey = builder.presharedKey;
        this.endpoint = builder.endpoint;
        this.allowedIps = Collections.unmodifiableList(new ArrayList<>(builder.allowedIps));
        this.persistentKeepaliveSeconds = builder.persistentKeepaliveSeconds;
    }

    public Key publicKey() {
        return publicKey;
    }

    public Key presharedKey() {
        return presharedKey;
    }

    public InetSocketAddress endpoint() {
        return endpoint;
    }

    public List<String> allowedIps() {
        return allowedIps;
    }

    public int persistentKeepaliveSeconds() {
        return persistentKeepaliveSeconds;
    }

    public static Builder builder(Key publicKey) {
        return new Builder(publicKey);
    }

    public static final class Builder {
        private final Key publicKey;
        private Key presharedKey;
        private InetSocketAddress endpoint;
        private final List<String> allowedIps = new ArrayList<>();
        private int persistentKeepaliveSeconds;

        private Builder(Key publicKey) {
            this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
        }

        public Builder presharedKey(Key presharedKey) {
            this.presharedKey = presharedKey;
            return this;
        }

        public Builder endpoint(InetSocketAddress endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder addAllowedIp(String cidr) {
            this.allowedIps.add(Objects.requireNonNull(cidr, "cidr"));
            return this;
        }

        public Builder persistentKeepaliveSeconds(int seconds) {
            this.persistentKeepaliveSeconds = seconds;
            return this;
        }

        public PeerConfig build() {
            if (persistentKeepaliveSeconds < 0) {
                throw new IllegalArgumentException("persistentKeepaliveSeconds < 0");
            }
            return new PeerConfig(this);
        }
    }
}
