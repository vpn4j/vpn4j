package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BytesTest {

    @Test
    void concatAndSlice() {
        assertArrayEquals(new byte[] {1, 2, 3, 4}, Bytes.concat(new byte[] {1, 2}, new byte[] {3, 4}));
        assertArrayEquals(
                new byte[] {1, 2, 3, 4, 5},
                Bytes.concat(new byte[] {1}, new byte[] {2, 3}, new byte[] {4, 5}));
        assertArrayEquals(new byte[] {3, 4}, Bytes.slice(new byte[] {1, 2, 3, 4, 5}, 2, 2));
    }

    @Test
    void endianHelpersRoundTrip() {
        byte[] buf = new byte[12];
        Bytes.putIntLe(buf, 0, 0x04030201);
        assertEquals(0x04030201, Bytes.getIntLe(buf, 0));
        Bytes.putLongLe(buf, 0, 0x0807060504030201L);
        assertEquals((byte) 0x01, buf[0]);
        assertEquals((byte) 0x08, buf[7]);
        Bytes.putLongBe(buf, 0, 0x0102030405060708L);
        assertEquals((byte) 0x01, buf[0]);
        assertEquals((byte) 0x08, buf[7]);
        Bytes.putIntBe(buf, 8, 0x0a0b0c0d);
        assertEquals((byte) 0x0a, buf[8]);
        assertEquals((byte) 0x0d, buf[11]);
    }

    @Test
    void constantTimeEqualsAndZero() {
        assertTrue(Bytes.constantTimeEquals(new byte[] {1, 2}, new byte[] {1, 2}));
        assertFalse(Bytes.constantTimeEquals(new byte[] {1, 2}, new byte[] {1, 3}));
        assertFalse(Bytes.constantTimeEquals(new byte[] {1}, new byte[] {1, 2}));
        byte[] a = new byte[] {9, 9, 9};
        Bytes.zero(a);
        assertArrayEquals(new byte[3], a);
    }
}
