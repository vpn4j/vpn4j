package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CookieFlowTest {

    @Test
    void underLoadRequiresCookieThenCompletes() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        PeerEngine a = new PeerEngine(
                aId,
                PeerConfig.builder(bId.publicKey()).endpoint(new InetSocketAddress("127.0.0.1", 2)).build(),
                pair.sideA(),
                new MemoryTunPort(),
                random,
                clock);
        PeerEngine b = new PeerEngine(
                bId,
                PeerConfig.builder(aId.publicKey()).endpoint(new InetSocketAddress("127.0.0.1", 1)).build(),
                pair.sideB(),
                new MemoryTunPort(),
                random,
                clock);
        b.setUnderLoad(true);

        a.initiate();
        assertTrue(b.pumpOnce());
        assertFalse(b.established());

        assertTrue(a.pumpOnce());
        assertTrue(a.hasCookie());

        a.initiate();
        assertTrue(b.pumpOnce());
        assertTrue(b.established());
        assertTrue(a.pumpOnce());
        assertTrue(a.established());

        a.close();
        b.close();
    }
}
