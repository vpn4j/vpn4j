package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.protocol.MessageSizes;
import com.github.vpn4j.protocol.ProtocolTimers;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerEngineEdgeTest {

    @Test
    void keepaliveRejectAgeRekeyAndEndpointGuards() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tunA = new MemoryTunPort();
        MemoryTunPort tunB = new MemoryTunPort();

        PeerEngine engineA = new PeerEngine(
                aId,
                PeerConfig.builder(bId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 2))
                        .build(),
                pair.sideA(),
                tunA,
                random,
                clock);
        PeerEngine engineB = new PeerEngine(
                bId,
                PeerConfig.builder(aId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 1))
                        .build(),
                pair.sideB(),
                tunB,
                random,
                clock);

        engineA.initiate();
        assertTrue(engineB.pumpOnce());
        assertTrue(engineA.pumpOnce());
        assertTrue(engineA.established());
        assertTrue(engineB.established());

        // Idle keepalive after receive window
        clock.advance(ProtocolTimers.KEEPALIVE_MS);
        assertTrue(engineB.tick());
        assertTrue(engineA.pumpOnce());
        assertTrue(engineA.established());

        // Rekey on initiator after REKEY_AFTER_TIME
        clock.advance(ProtocolTimers.REKEY_AFTER_TIME_MS);
        assertTrue(engineA.tick());
        assertTrue(engineA.hasPendingHandshake() || engineA.established());

        // Fresh pair for reject-by-age
        ManualClock clock2 = new ManualClock(0L);
        InMemoryCarrierPair pair2 = new InMemoryCarrierPair();
        MemoryTunPort tunA2 = new MemoryTunPort();
        MemoryTunPort tunB2 = new MemoryTunPort();
        PeerEngine a2 = new PeerEngine(
                aId,
                PeerConfig.builder(bId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 2))
                        .build(),
                pair2.sideA(),
                tunA2,
                random,
                clock2);
        PeerEngine b2 = new PeerEngine(
                bId,
                PeerConfig.builder(aId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 1))
                        .build(),
                pair2.sideB(),
                tunB2,
                random,
                clock2);
        a2.initiate();
        assertTrue(b2.pumpOnce());
        assertTrue(a2.pumpOnce());
        clock2.advance(ProtocolTimers.REJECT_AFTER_TIME_MS);
        assertThrows(IllegalStateException.class, () -> a2.handleTunOutbound(new byte[] {1}, 1));
        assertFalse(a2.established());

        PeerEngine noEp = new PeerEngine(
                aId, PeerConfig.builder(bId.publicKey()).build(), pair.sideA(), tunA, random, clock);
        assertThrows(IllegalStateException.class, noEp::initiate);

        engineA.close();
        assertThrows(IllegalStateException.class, engineA::initiate);
        assertThrows(IllegalStateException.class, engineA::pumpOnce);

        engineB.close();
        a2.close();
        b2.close();
        noEp.close();
        tunA.close();
        tunB.close();
        tunA2.close();
        tunB2.close();
    }

    @Test
    void tryHandleWireAndDataBeforeSession() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);
        KeyPair foreign = X25519.generate(random);

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tun = new MemoryTunPort();
        PeerEngine engine = new PeerEngine(
                bId,
                PeerConfig.builder(aId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 1))
                        .build(),
                pair.sideB(),
                tun,
                random,
                clock);

        // Foreign initiation mac1 fails → tryHandleWire false
        PeerEngine foreignInit = new PeerEngine(
                foreign,
                PeerConfig.builder(bId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 2))
                        .build(),
                pair.sideA(),
                new MemoryTunPort(),
                random,
                clock);
        foreignInit.initiate();
        byte[] buf = new byte[65535];
        int n = pair.sideB().receive(buf);
        assertTrue(n > 0);
        assertFalse(engine.tryHandleWire(buf, n));

        // DATA before session
        byte[] data = new byte[MessageSizes.DATA_MINIMUM];
        data[0] = 4;
        assertFalse(engine.handleWire(data, data.length));

        engine.close();
        foreignInit.close();
        tun.close();
    }
}
