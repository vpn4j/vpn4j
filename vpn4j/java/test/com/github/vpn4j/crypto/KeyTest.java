package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyTest {

    @Test
    void constructorRejectsBadLength() {
        assertThrows(IllegalArgumentException.class, () -> new Key(new byte[16]));
        assertThrows(NullPointerException.class, () -> new Key(null));
    }

    @Test
    void bytesIsDefensiveCopy() {
        byte[] raw = new byte[32];
        Arrays.fill(raw, (byte) 9);
        Key key = new Key(raw);
        raw[0] = 0;
        byte[] view = key.bytes();
        view[1] = 1;
        assertEquals(9, key.bytes()[0] & 0xff);
        assertEquals(9, key.bytes()[1] & 0xff);
        assertEquals(32, key.length());
    }

    @Test
    void equalsAndConstantTime() {
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        Arrays.fill(a, (byte) 1);
        Arrays.fill(b, (byte) 1);
        Key ka = new Key(a);
        Key kb = new Key(b);
        assertTrue(ka.equalsConstantTime(kb));
        assertEquals(ka, kb);
        assertEquals(ka.hashCode(), kb.hashCode());

        b[31] = 2;
        Key kc = new Key(b);
        assertFalse(ka.equalsConstantTime(kc));
        assertNotEquals(ka, kc);
        assertFalse(ka.equalsConstantTime(null));
        assertFalse(ka.equals("nope"));
        assertTrue(ka.equals(ka)); // same reference branch
    }
}
