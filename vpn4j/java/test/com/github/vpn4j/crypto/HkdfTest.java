package com.github.vpn4j.crypto;

import com.github.vpn4j.protocol.ProtocolConstants;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class HkdfTest {

    @Test
    void kdfLengthsAndConsistency() {
        byte[] ck = Blake2s.hash32(ProtocolConstants.CONSTRUCTION);
        byte[] input = "vpn4j".getBytes(StandardCharsets.US_ASCII);

        byte[] k1 = Hkdf.kdf1(ck, input);
        assertEquals(32, k1.length);

        byte[][] k2 = Hkdf.kdf2(ck, input);
        assertEquals(2, k2.length);
        assertEquals(32, k2[0].length);
        assertEquals(32, k2[1].length);
        assertArrayEquals(k1, k2[0]);
        assertFalse(Arrays.equals(k2[0], k2[1]));

        byte[][] k3 = Hkdf.kdf3(ck, input);
        assertEquals(3, k3.length);
        assertArrayEquals(k2[0], k3[0]);
        assertArrayEquals(k2[1], k3[1]);
        assertFalse(Arrays.equals(k3[1], k3[2]));
    }

    @Test
    void deterministicAndEmptyInput() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 1);
        byte[] a = Hkdf.kdf1(key, new byte[0]);
        byte[] b = Hkdf.kdf1(key, new byte[0]);
        assertArrayEquals(a, b);
    }

    @Test
    void hmacHashesLongKeyFirst() {
        byte[] longKey = new byte[80];
        Arrays.fill(longKey, (byte) 0xab);
        byte[] data = new byte[] {1, 2, 3};
        byte[] hashedKey = Blake2s.hash32(longKey);
        byte[] viaLong = Hkdf.hmac(longKey, data);
        byte[] viaHashed = Hkdf.hmac(hashedKey, data);
        assertArrayEquals(viaHashed, viaLong);
    }
}
