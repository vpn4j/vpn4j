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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeviceEngineEdgeTest {

    @Test
    void duplicatePeerUnknownInitiateGarbageAndClose() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);
        KeyPair unknown = X25519.generate(random);

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tun = new MemoryTunPort();
        DeviceEngine device = new DeviceEngine(aId, pair.sideA(), tun, random, clock);

        PeerConfig peer = PeerConfig.builder(bId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 2))
                .addAllowedIp("10.0.0.2/32")
                .build();
        device.addPeer(peer);
        assertThrows(IllegalArgumentException.class, () -> device.addPeer(peer));
        assertThrows(IllegalArgumentException.class, () -> device.initiate(unknown.publicKey()));

        assertFalse(device.demuxWire(new byte[] {0, 0, 0, 0}, 4));
        assertFalse(device.demuxWire(new byte[] {4, 0, 0, 0}, 4));

        device.close();
        assertThrows(IllegalStateException.class, () -> device.addPeer(peer));
        assertThrows(IllegalStateException.class, device::pumpOnce);
        tun.close();
    }

    @Test
    void cookieDemuxUnderLoad() throws Exception {
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
                .build());
        deviceB.addPeer(PeerConfig.builder(aId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 1))
                .build());

        deviceB.setUnderLoad(true);
        deviceA.initiate(bId.publicKey());
        deviceB.pumpOnce(); // cookie reply; demux returns false until established
        assertTrue(deviceA.pumpOnce());
        assertTrue(deviceA.peer(bId.publicKey()).hasCookie());

        // Retry with cookie should complete handshake
        deviceA.initiate(bId.publicKey());
        assertTrue(deviceB.pumpOnce());
        assertTrue(deviceA.pumpOnce());
        assertTrue(deviceA.peer(bId.publicKey()).established());
        assertTrue(deviceB.peer(aId.publicKey()).established());

        deviceA.close();
        deviceB.close();
        tunA.close();
        tunB.close();
    }
}
