package com.github.vpn4j.transport;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UdpCarrierTest {

    @Test
    void localhostRoundTripNonBlocking() throws Exception {
        try (UdpCarrier a = UdpCarrier.bind(0); UdpCarrier b = UdpCarrier.bind(0)) {
            InetSocketAddress bAddr = (InetSocketAddress) b.channel().getLocalAddress();
            byte[] payload = "udp-ok".getBytes(StandardCharsets.US_ASCII);
            a.send(payload, new InetSocketAddress("127.0.0.1", bAddr.getPort()));

            byte[] dst = new byte[64];
            int n = 0;
            for (int i = 0; i < 50 && n == 0; i++) {
                n = b.receive(dst);
                if (n == 0) {
                    Thread.sleep(10);
                }
            }
            assertEquals(payload.length, n);
            assertArrayEquals(payload, java.util.Arrays.copyOf(dst, n));
            assertTrue(b.lastRemote() instanceof InetSocketAddress);

            assertEquals(0, a.receive(dst));
        }
    }
}
