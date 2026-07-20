package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

class PacketPaddingTest {

    @Test
    void emptyUnchanged() {
        assertEquals(0, PacketPadding.pad(new byte[0]).length);
        assertEquals(0, PacketPadding.pad(null).length);
    }

    @Test
    void padsToMultipleOf16() {
        assertEquals(16, PacketPadding.pad(new byte[1]).length);
        assertEquals(16, PacketPadding.pad(new byte[16]).length);
        assertEquals(32, PacketPadding.pad(new byte[17]).length);
    }

    @Test
    void preservesPrefixAndClonesExactMultiple() {
        byte[] in = new byte[] {1, 2, 3, 4, 5};
        byte[] padded = PacketPadding.pad(in);
        assertArrayEquals(in, Arrays.copyOf(padded, in.length));
        for (int i = in.length; i < padded.length; i++) {
            assertEquals(0, padded[i]);
        }

        byte[] exact = new byte[16];
        Arrays.fill(exact, (byte) 7);
        byte[] cloned = PacketPadding.pad(exact);
        assertNotSame(exact, cloned);
        assertArrayEquals(exact, cloned);
        exact[0] = 0;
        assertEquals(7, cloned[0]);
    }
}
