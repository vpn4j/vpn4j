package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.Bytes;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.protocol.MessageSizes;
import com.github.vpn4j.protocol.MessageType;
import com.github.vpn4j.protocol.ProtocolTimers;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerEngineCoverageTest {

    @Test
    void accessorsAndHandleWireGuards() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);
        PeerConfig cfg = PeerConfig.builder(bId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 2))
                .build();
        PeerEngine engine = new PeerEngine(
                aId, cfg, new InMemoryCarrierPair().sideA(), new MemoryTunPort(), random, clock);

        assertFalse(engine.underLoad());
        engine.setUnderLoad(true);
        assertTrue(engine.underLoad());
        assertSame(cfg, engine.peer());
        assertNull(engine.session());
        assertNotNull(engine.timers());
        assertFalse(engine.handleWire(null, 10));
        assertFalse(engine.handleWire(new byte[4], 0));
        assertFalse(engine.handleWire(new byte[] {0, 0, 0, 0}, 4)); // INVALID type

        byte[] zeroInit = new byte[MessageSizes.HANDSHAKE_INITIATION];
        zeroInit[0] = (byte) MessageType.HANDSHAKE_INITIATION.wire();
        assertThrows(IllegalArgumentException.class, () -> engine.handleWire(zeroInit, zeroInit.length));

        byte[] badInit = new byte[10];
        badInit[0] = (byte) MessageType.HANDSHAKE_INITIATION.wire();
        assertThrows(IllegalArgumentException.class, () -> engine.handleWire(badInit, badInit.length));

        byte[] badCookie = new byte[8];
        badCookie[0] = (byte) MessageType.HANDSHAKE_COOKIE.wire();
        assertThrows(IllegalArgumentException.class, () -> engine.handleWire(badCookie, badCookie.length));

        byte[] cookie = new byte[MessageSizes.HANDSHAKE_COOKIE];
        cookie[0] = (byte) MessageType.HANDSHAKE_COOKIE.wire();
        Bytes.putIntLe(cookie, 4, engine.localIndex() ^ 1);
        assertThrows(IllegalArgumentException.class, () -> engine.handleWire(cookie, cookie.length));

        Bytes.putIntLe(cookie, 4, engine.localIndex());
        assertThrows(IllegalStateException.class, () -> engine.handleWire(cookie, cookie.length));

        byte[] badResp = new byte[10];
        badResp[0] = (byte) MessageType.HANDSHAKE_RESPONSE.wire();
        assertThrows(IllegalArgumentException.class, () -> engine.handleWire(badResp, badResp.length));

        byte[] resp = new byte[MessageSizes.HANDSHAKE_RESPONSE];
        resp[0] = (byte) MessageType.HANDSHAKE_RESPONSE.wire();
        Bytes.putIntLe(resp, 8, engine.localIndex() ^ 1);
        assertThrows(IllegalArgumentException.class, () -> engine.handleWire(resp, resp.length));

        Bytes.putIntLe(resp, 8, engine.localIndex());
        assertThrows(IllegalStateException.class, () -> engine.handleWire(resp, resp.length));

        engine.close();
    }

    @Test
    void rejectByAgeClearsSessionOnTickAndData() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);
        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tunA = new MemoryTunPort();
        MemoryTunPort tunB = new MemoryTunPort();

        PeerEngine a = new PeerEngine(
                aId,
                PeerConfig.builder(bId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 2))
                        .build(),
                pair.sideA(),
                tunA,
                random,
                clock);
        PeerEngine b = new PeerEngine(
                bId,
                PeerConfig.builder(aId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 1))
                        .build(),
                pair.sideB(),
                tunB,
                random,
                clock);

        a.initiate();
        assertTrue(b.pumpOnce());
        assertTrue(a.pumpOnce());
        assertNotNull(a.session());

        clock.advance(ProtocolTimers.REJECT_AFTER_TIME_MS);
        assertFalse(a.tick());
        assertFalse(a.established());
        assertNull(a.session());

        // Re-establish then age out on inbound data
        a.initiate();
        assertTrue(b.pumpOnce());
        assertTrue(a.pumpOnce());
        byte[] wire = a.session().seal(new byte[] {1});
        clock.advance(ProtocolTimers.REJECT_AFTER_TIME_MS);
        assertFalse(b.handleWire(wire, wire.length));
        assertFalse(b.established());

        a.close();
        b.close();
        tunA.close();
        tunB.close();
    }

    @Test
    void unresolvedEndpointUsesZeroAddressBytesUnderLoad() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);
        InMemoryCarrierPair pair = new InMemoryCarrierPair();

        // Responder with unresolved endpoint — addressBytes falls back to 0.0.0.0
        PeerEngine b = new PeerEngine(
                bId,
                PeerConfig.builder(aId.publicKey())
                        .endpoint(InetSocketAddress.createUnresolved("peer.example", 51820))
                        .build(),
                pair.sideB(),
                new MemoryTunPort(),
                random,
                clock);
        b.setUnderLoad(true);

        PeerEngine a = new PeerEngine(
                aId,
                PeerConfig.builder(bId.publicKey())
                        .endpoint(new InetSocketAddress("127.0.0.1", 2))
                        .build(),
                pair.sideA(),
                new MemoryTunPort(),
                random,
                clock);

        a.initiate();
        assertTrue(b.pumpOnce()); // cookie reply path
        assertFalse(b.established());
        assertTrue(a.pumpOnce());
        assertTrue(a.hasCookie());
        assertTrue(a.peerPublicKey().equalsConstantTime(a.peer().publicKey()));

        a.close();
        b.close();
    }
}
