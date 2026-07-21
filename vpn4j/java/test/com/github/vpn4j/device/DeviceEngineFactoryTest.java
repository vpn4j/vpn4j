package com.github.vpn4j.device;

import com.github.vpn4j.config.DeviceConfig;
import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.config.TransportMode;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.engine.DeviceEngine;
import com.github.vpn4j.engine.PeerEngine;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeviceEngineFactoryTest {

    @Test
    void engineForAndDeviceEngine() {
        SecureRandom random = new SecureRandom();
        KeyPair identity = X25519.generate(random);
        KeyPair peer = X25519.generate(random);
        DeviceConfig cfg = DeviceConfig.builder().transportMode(TransportMode.TUN).listenPort(0).build();
        Device device = new Device(cfg, identity, random);

        assertSame(cfg, device.config());
        assertSame(identity, device.identity());
        assertEquals(TransportMode.TUN, device.transportMode());

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tun = new MemoryTunPort();
        PeerConfig peerCfg = PeerConfig.builder(peer.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 2))
                .build();
        PeerEngine pe = device.engineFor(peerCfg, pair.sideA(), tun);
        assertNotNull(pe);
        assertTrue(pe.peerPublicKey().equalsConstantTime(peer.publicKey()));

        DeviceEngine de = device.deviceEngine(pair.sideB(), tun);
        assertNotNull(de);
        de.addPeer(peerCfg);
        assertEquals(1, de.peers().size());

        device.close();
        assertThrows(IllegalStateException.class, () -> device.engineFor(peerCfg, pair.sideA(), tun));
        tun.close();
    }
}
