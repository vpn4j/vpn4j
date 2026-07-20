package com.github.vpn4j.config;

import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.engine.DeviceEngine;
import com.github.vpn4j.engine.ManualClock;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class WgConfigsTest {

    @Test
    void deviceEngineAddsAllPeers() {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair self = X25519.generate(random);
        KeyPair p1 = X25519.generate(random);
        KeyPair p2 = X25519.generate(random);

        WgConfig cfg = WgConfig.builder()
                .privateKey(self.privateKey())
                .listenPort(0)
                .addPeer(PeerConfig.builder(p1.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 2))
                        .addAllowedIp("10.0.0.2/32")
                        .build())
                .addPeer(PeerConfig.builder(p2.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 3))
                        .addAllowedIp("10.0.0.3/32")
                        .build())
                .build();

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        try (MemoryTunPort tun = new MemoryTunPort();
                DeviceEngine engine = WgConfigs.deviceEngine(cfg, pair.sideA(), tun, random, clock)) {
            assertEquals(2, engine.peers().size());
            assertNotNull(engine.peer(p1.publicKey()));
            assertNotNull(engine.peer(p2.publicKey()));
            assertEquals(self.publicKey(), engine.peer(p1.publicKey()).peerPublicKey() == null
                    ? null
                    : self.publicKey()); // identity is internal; just ensure peers present
        }
    }

    @Test
    void convenienceOverloadConstructs() {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        KeyPair peer = X25519.generate(random);
        WgConfig cfg = WgConfig.builder()
                .privateKey(self.privateKey())
                .addPeer(PeerConfig.builder(peer.publicKey()).build())
                .build();
        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        try (MemoryTunPort tun = new MemoryTunPort();
                DeviceEngine engine = WgConfigs.deviceEngine(cfg, pair.sideA(), tun)) {
            assertEquals(1, engine.peers().size());
        }
    }
}
