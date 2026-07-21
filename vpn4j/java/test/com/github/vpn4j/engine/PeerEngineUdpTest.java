package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.transport.UdpCarrier;
import com.github.vpn4j.tun.MemoryTunPort;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerEngineUdpTest {

    @Test
    void handshakeAndDataOverUdp() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);

        try (UdpCarrier carrierA = UdpCarrier.bind(0); UdpCarrier carrierB = UdpCarrier.bind(0)) {
            int portA = ((InetSocketAddress) carrierA.channel().getLocalAddress()).getPort();
            int portB = ((InetSocketAddress) carrierB.channel().getLocalAddress()).getPort();
            MemoryTunPort tunA = new MemoryTunPort();
            MemoryTunPort tunB = new MemoryTunPort();

            PeerEngine engineA = new PeerEngine(
                    aId,
                    PeerConfig.builder(bId.publicKey())
                            .endpoint(new InetSocketAddress("127.0.0.1", portB))
                            .build(),
                    carrierA,
                    tunA,
                    random);
            PeerEngine engineB = new PeerEngine(
                    bId,
                    PeerConfig.builder(aId.publicKey())
                            .endpoint(new InetSocketAddress("127.0.0.1", portA))
                            .build(),
                    carrierB,
                    tunB,
                    random);

            engineA.initiate();
            long deadline = System.currentTimeMillis() + 5_000L;
            while (System.currentTimeMillis() < deadline
                    && !(engineA.established() && engineB.established())) {
                engineB.pumpOnce();
                engineA.pumpOnce();
                Thread.sleep(5L);
            }
            assertTrue(engineA.established() && engineB.established());

            byte[] payload = "udp-path".getBytes(StandardCharsets.US_ASCII);
            tunA.injectFromOs(payload);
            byte[] got = null;
            deadline = System.currentTimeMillis() + 5_000L;
            while (System.currentTimeMillis() < deadline && got == null) {
                engineA.pumpOnce();
                engineB.pumpOnce();
                got = tunB.pollToOs(20);
            }
            assertNotNull(got);
            assertArrayEquals(payload, Arrays.copyOf(got, payload.length));

            engineA.close();
            engineB.close();
            tunA.close();
            tunB.close();
        }
    }
}
