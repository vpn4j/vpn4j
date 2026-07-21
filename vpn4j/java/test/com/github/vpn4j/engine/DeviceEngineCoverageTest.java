package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.Bytes;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.protocol.MessageType;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeviceEngineCoverageTest {

    @Test
    void defaultConstructorAndDemuxMisses() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        KeyPair peer = X25519.generate(random);
        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tun = new MemoryTunPort();

        DeviceEngine device = new DeviceEngine(self, pair.sideA(), tun);
        device.addPeer(PeerConfig.builder(peer.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 2))
                .addAllowedIp("10.0.0.2/32")
                .build());
        assertNotNull(device.peer(peer.publicKey()));

        assertFalse(device.demuxWire(new byte[] {3, 0, 0, 0}, 4)); // cookie too short
        byte[] cookie = new byte[16];
        cookie[0] = (byte) MessageType.HANDSHAKE_COOKIE.wire();
        Bytes.putIntLe(cookie, 4, 0xdeadbeef); // no matching local index
        assertFalse(device.demuxWire(cookie, cookie.length));

        assertFalse(device.demuxWire(new byte[] {2, 0, 0, 0, 0, 0, 0, 0}, 8)); // response too short
        byte[] resp = new byte[16];
        resp[0] = (byte) MessageType.HANDSHAKE_RESPONSE.wire();
        Bytes.putIntLe(resp, 8, 0xbeef); // echo index miss / no pending
        assertFalse(device.demuxWire(resp, resp.length));

        byte[] data = new byte[16];
        data[0] = (byte) MessageType.DATA.wire();
        Bytes.putIntLe(data, 4, 0xcafe); // receiver index miss
        assertFalse(device.demuxWire(data, data.length));

        // TUN packet with no established route
        byte[] ip = new byte[20];
        ip[0] = 0x45;
        ip[16] = 10;
        ip[19] = 2;
        tun.injectFromOs(ip);
        assertFalse(device.pumpOnce());

        device.close();
        tun.close();
    }

    @Test
    void tickTrueWhenPeerWantsKeepalive() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);
        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tunA = new MemoryTunPort();
        MemoryTunPort tunB = new MemoryTunPort();

        DeviceEngine deviceA = new DeviceEngine(aId, pair.sideA(), tunA, random, clock);
        DeviceEngine deviceB = new DeviceEngine(bId, pair.sideB(), tunB, random, clock);
        deviceA.addPeer(PeerConfig.builder(bId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 2))
                .addAllowedIp("10.0.0.2/32")
                .build());
        deviceB.addPeer(PeerConfig.builder(aId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 1))
                .addAllowedIp("10.0.0.1/32")
                .build());

        deviceA.initiate(bId.publicKey());
        assertTrue(deviceB.pumpOnce());
        assertTrue(deviceA.pumpOnce());
        clock.advance(com.github.vpn4j.protocol.ProtocolTimers.KEEPALIVE_MS);
        assertTrue(deviceA.pumpOnce() || deviceB.pumpOnce());

        deviceA.close();
        deviceB.close();
        tunA.close();
        tunB.close();
    }
}
