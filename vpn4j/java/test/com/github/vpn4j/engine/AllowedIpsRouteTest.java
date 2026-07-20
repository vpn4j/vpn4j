package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.transport.InMemoryCarrierPair;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class AllowedIpsRouteTest {

    @Test
    void longestPrefixAmongPeers() throws Exception {
        SecureRandom random = new SecureRandom();
        ManualClock clock = new ManualClock(0L);
        KeyPair self = X25519.generate(random);
        KeyPair peerWide = X25519.generate(random);
        KeyPair peerExact = X25519.generate(random);

        DeviceEngine device = new DeviceEngine(
                self, new InMemoryCarrierPair().sideA(), new MemoryTunPort(), random, clock);

        PeerEngine wide = device.addPeer(PeerConfig.builder(peerWide.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 1))
                .addAllowedIp("10.0.0.0/8")
                .build());
        PeerEngine exact = device.addPeer(PeerConfig.builder(peerExact.publicKey())
                .endpoint(new InetSocketAddress("127.0.0.1", 2))
                .addAllowedIp("10.1.2.0/24")
                .build());

        byte[] toExact = ipv4("10.1.2.9");
        byte[] toWide = ipv4("10.9.9.9");
        byte[] miss = ipv4("11.0.0.1");

        assertSame(exact, device.lookupAllowedIp(toExact, toExact.length));
        assertSame(wide, device.lookupAllowedIp(toWide, toWide.length));
        assertNull(device.lookupAllowedIp(miss, miss.length));
        // Not established → route drops
        assertNull(device.routeByAllowedIps(toExact, toExact.length));
    }

    private static byte[] ipv4(String dst) throws Exception {
        byte[] d = java.net.InetAddress.getByName(dst).getAddress();
        byte[] pkt = new byte[20];
        pkt[0] = 0x45;
        System.arraycopy(d, 0, pkt, 16, 4);
        return pkt;
    }
}
