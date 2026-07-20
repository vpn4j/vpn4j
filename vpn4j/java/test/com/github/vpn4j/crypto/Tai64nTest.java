package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Tai64nTest {

    @Test
    void ofEncodesBigEndianLayout() {
        assertArrayEquals(new byte[12], Tai64n.of(0L, 0));
        byte[] ts = Tai64n.of(0x0102030405060708L, 0x0a0b0c0d);
        assertArrayEquals(
                new byte[] {
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c, 0x0d
                },
                ts);
    }

    @Test
    void nowIsTwelveBytesNearWallClockPlusLeapOffset() {
        long before = System.currentTimeMillis();
        byte[] now = Tai64n.now();
        long after = System.currentTimeMillis();
        assertEquals(12, now.length);

        long seconds = 0L;
        for (int i = 0; i < 8; i++) {
            seconds = (seconds << 8) | (now[i] & 0xffL);
        }
        long minTai = before / 1000L + 37L;
        long maxTai = after / 1000L + 37L + 1L;
        assertTrue(seconds >= minTai && seconds <= maxTai, "seconds=" + seconds);
    }
}
