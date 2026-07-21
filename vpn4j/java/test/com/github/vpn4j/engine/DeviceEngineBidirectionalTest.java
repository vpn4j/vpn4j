package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeviceEngineBidirectionalTest {

    @Test
    void bothDirectionsOverSharedCarrier() throws Exception {
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

        byte[] aToB = ipv4("10.0.0.1", "10.0.0.2", new byte[] {9, 9});
        tunA.injectFromOs(aToB);
        assertTrue(deviceA.pumpOnce());
        assertTrue(deviceB.pumpOnce());
        byte[] deliveredB = tunB.pollToOs(1000);
        assertNotNull(deliveredB);
        assertArrayEquals(aToB, Arrays.copyOf(deliveredB, aToB.length));

        byte[] bToA = ipv4("10.0.0.2", "10.0.0.1", new byte[] {8, 8});
        tunB.injectFromOs(bToA);
        assertTrue(deviceB.pumpOnce());
        assertTrue(deviceA.pumpOnce());
        byte[] deliveredA = tunA.pollToOs(1000);
        assertNotNull(deliveredA);
        assertArrayEquals(bToA, Arrays.copyOf(deliveredA, bToA.length));

        deviceA.close();
        deviceB.close();
        tunA.close();
        tunB.close();
    }

    private static byte[] ipv4(String src, String dst, byte[] payload) throws Exception {
        byte[] s = java.net.InetAddress.getByName(src).getAddress();
        byte[] d = java.net.InetAddress.getByName(dst).getAddress();
        byte[] pkt = new byte[20 + payload.length];
        pkt[0] = 0x45;
        pkt[2] = (byte) (pkt.length >>> 8);
        pkt[3] = (byte) pkt.length;
        pkt[8] = 64;
        pkt[9] = 17;
        System.arraycopy(s, 0, pkt, 12, 4);
        System.arraycopy(d, 0, pkt, 16, 4);
        System.arraycopy(payload, 0, pkt, 20, payload.length);
        return pkt;
    }
}
