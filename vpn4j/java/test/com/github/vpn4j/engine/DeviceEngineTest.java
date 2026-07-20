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

class DeviceEngineTest {

    @Test
    void demuxHandshakeAndRouteIpv4() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);

        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        MemoryTunPort tunA = new MemoryTunPort();
        MemoryTunPort tunB = new MemoryTunPort();

        DeviceEngine deviceA = new DeviceEngine(aId, pair.sideA(), tunA, random, clock);
        DeviceEngine deviceB = new DeviceEngine(bId, pair.sideB(), tunB, random, clock);

        PeerConfig aToB = PeerConfig.builder(bId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 2))
                .addAllowedIp("10.0.0.2/32")
                .build();
        PeerConfig bToA = PeerConfig.builder(aId.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 1))
                .addAllowedIp("10.0.0.1/32")
                .build();

        // Extra decoy peer on B — demux must pick the real initiator key.
        KeyPair decoy = X25519.generate(random);
        deviceB.addPeer(PeerConfig.builder(decoy.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 9))
                .build());
        deviceB.addPeer(bToA);
        deviceA.addPeer(aToB);

        deviceA.initiate(bId.publicKey());
        assertTrue(deviceB.pumpOnce());
        assertTrue(deviceB.peer(aId.publicKey()).established());
        assertTrue(deviceA.pumpOnce());
        assertTrue(deviceA.peer(bId.publicKey()).established());

        byte[] ip = ipv4Packet("10.0.0.1", "10.0.0.2", new byte[] {1, 2, 3, 4});
        tunA.injectFromOs(ip);
        assertTrue(deviceA.pumpOnce());
        assertTrue(deviceB.pumpOnce());

        byte[] delivered = tunB.pollToOs(1000);
        assertNotNull(delivered);
        assertArrayEquals(ip, Arrays.copyOf(delivered, ip.length));

        deviceA.close();
        deviceB.close();
        tunA.close();
        tunB.close();
        pair.sideA().close();
        pair.sideB().close();
    }

    private static byte[] ipv4Packet(String src, String dst, byte[] payload) throws Exception {
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
