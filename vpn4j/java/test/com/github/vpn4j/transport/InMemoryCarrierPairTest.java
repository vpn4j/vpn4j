package com.github.vpn4j.transport;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InMemoryCarrierPairTest {

    @Test
    void bidirectionalCloneAndLastRemote() throws Exception {
        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        PacketCarrier a = pair.sideA();
        PacketCarrier b = pair.sideB();

        byte[] payload = new byte[] {9, 8, 7};
        a.send(payload, null);
        payload[0] = 0;

        byte[] dst = new byte[16];
        assertEquals(3, b.receive(dst));
        assertArrayEquals(new byte[] {9, 8, 7}, java.util.Arrays.copyOf(dst, 3));
        assertEquals(new InetSocketAddress("127.0.0.1", 1), b.lastRemote());

        b.send(new byte[] {1}, null);
        assertEquals(1, a.receive(dst));
        assertEquals(1, dst[0]);
        assertEquals(new InetSocketAddress("127.0.0.1", 2), a.lastRemote());
    }

    @Test
    void receiveTimeoutAndBufferTooSmall() throws Exception {
        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        PacketCarrier a = pair.sideA();
        PacketCarrier b = pair.sideB();
        assertEquals(0, b.receive(new byte[8]));

        a.send(new byte[8], null);
        assertThrows(IOException.class, () -> b.receive(new byte[4]));
    }

    @Test
    void closedRejectsIo() throws IOException {
        InMemoryCarrierPair pair = new InMemoryCarrierPair();
        PacketCarrier a = pair.sideA();
        a.close();
        assertThrows(IOException.class, () -> a.send(new byte[1], null));
        assertThrows(IOException.class, () -> a.receive(new byte[8]));
    }
}
