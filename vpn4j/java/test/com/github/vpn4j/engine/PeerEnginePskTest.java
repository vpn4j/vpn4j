package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerEnginePskTest {

    @Test
    void matchingPskCompletesHandshakeAndData() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);
        byte[] pskRaw = new byte[32];
        random.nextBytes(pskRaw);
        Key psk = new Key(pskRaw);

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tunA = new MemoryTunPort();
        MemoryTunPort tunB = new MemoryTunPort();

        PeerEngine a = new PeerEngine(
                aId,
                PeerConfig.builder(bId.publicKey())
                        .presharedKey(psk)
                        .endpoint(new InetSocketAddress("127.0.0.1", 2))
                        .build(),
                pair.sideA(),
                tunA,
                random,
                clock);
        PeerEngine b = new PeerEngine(
                bId,
                PeerConfig.builder(aId.publicKey())
                        .presharedKey(psk)
                        .endpoint(new InetSocketAddress("127.0.0.1", 1))
                        .build(),
                pair.sideB(),
                tunB,
                random,
                clock);

        a.initiate();
        assertTrue(b.pumpOnce());
        assertTrue(a.pumpOnce());
        assertTrue(a.established() && b.established());

        byte[] payload = "psk-ok".getBytes(StandardCharsets.US_ASCII);
        tunA.injectFromOs(payload);
        assertTrue(a.pumpOnce());
        assertTrue(b.pumpOnce());
        assertArrayEquals(payload, Arrays.copyOf(tunB.pollToOs(1000), payload.length));

        a.close();
        b.close();
        tunA.close();
        tunB.close();
    }

    @Test
    void mismatchedPskDoesNotEstablish() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);
        Key pskA = new Key(new byte[32]);
        byte[] other = new byte[32];
        other[0] = 1;
        Key pskB = new Key(other);

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        PeerEngine a = new PeerEngine(
                aId,
                PeerConfig.builder(bId.publicKey())
                        .presharedKey(pskA)
                        .endpoint(new InetSocketAddress("127.0.0.1", 2))
                        .build(),
                pair.sideA(),
                new MemoryTunPort(),
                random,
                clock);
        PeerEngine b = new PeerEngine(
                bId,
                PeerConfig.builder(aId.publicKey())
                        .presharedKey(pskB)
                        .endpoint(new InetSocketAddress("127.0.0.1", 1))
                        .build(),
                pair.sideB(),
                new MemoryTunPort(),
                random,
                clock);

        a.initiate();
        assertTrue(b.pumpOnce());
        // Responder may mark session up locally; initiator AEAD fails on mismatched PSK.
        IllegalStateException failed = assertThrows(IllegalStateException.class, () -> a.pumpOnce());
        assertTrue(failed.getMessage().contains("AEAD") || failed.getCause() != null);
        assertFalse(a.established());
        a.close();
        b.close();
    }
}
