package com.github.vpn4j.engine;

import com.github.vpn4j.config.DeviceConfig;
import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.device.Device;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerEngineTest {

    @Test
    void handshakeAndTunDataPath() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair initiatorId = X25519.generate(random);
        KeyPair responderId = X25519.generate(random);

        Device initiatorDev = new Device(DeviceConfig.builder().listenPort(0).build(), initiatorId, random);
        Device responderDev = new Device(DeviceConfig.builder().listenPort(0).build(), responderId, random);

        PeerConfig toResponder = PeerConfig.builder(responderId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 2))
                .addAllowedIp("10.0.0.2/32")
                .build();
        PeerConfig toInitiator = PeerConfig.builder(initiatorId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 1))
                .addAllowedIp("10.0.0.1/32")
                .build();

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tunA = new MemoryTunPort();
        MemoryTunPort tunB = new MemoryTunPort();

        PeerEngine engineA = initiatorDev.engineFor(toResponder, pair.sideA(), tunA);
        PeerEngine engineB = responderDev.engineFor(toInitiator, pair.sideB(), tunB);

        engineA.initiate();

        // initiation A→B, response B→A
        assertTrue(engineB.pumpOnce());
        assertTrue(engineB.established());
        assertTrue(engineA.pumpOnce());
        assertTrue(engineA.established());

        byte[] payload = "ping-from-a".getBytes(StandardCharsets.US_ASCII);
        tunA.injectFromOs(payload);
        assertTrue(engineA.pumpOnce());
        assertTrue(engineB.pumpOnce());

        byte[] delivered = tunB.pollToOs(1000);
        assertNotNull(delivered);
        assertArrayEquals(payload, Arrays.copyOf(delivered, payload.length));

        engineA.close();
        engineB.close();
        pair.sideA().close();
        pair.sideB().close();
        tunA.close();
        tunB.close();
        initiatorDev.close();
        responderDev.close();
    }
}
