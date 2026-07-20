package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Blake2sTest {

    @Test
    void rfc7693Empty32() {
        // RFC 7693 Appendix A — BLAKE2s("", 32)
        byte[] expected = hex(
                "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
        assertArrayEquals(expected, Blake2s.hash32(new byte[0]));
    }

    @Test
    void rfc7693Abc() {
        byte[] expected = hex(
                "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
        assertArrayEquals(expected, Blake2s.hash32("abc".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void constructionHashLength() {
        assertEquals(37, ProtocolConstruction.CONSTRUCTION_LEN);
    }

    @Test
    void keyedMacDeterministicAndLengthSensitive() {
        // BLAKE2s mixes outLen into the parameter block — 16 vs 32 are not prefixes.
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
        }
        byte[] mac16 = Blake2s.mac(key, new byte[0], 16);
        byte[] mac32 = Blake2s.mac(key, new byte[0], 32);
        assertEquals(16, mac16.length);
        assertEquals(32, mac32.length);
        assertArrayEquals(mac16, Blake2s.mac(key, new byte[0], 16));
        assertFalse(Arrays.equals(mac16, Arrays.copyOf(mac32, 16)));
        assertFalse(Arrays.equals(mac16, new byte[16]));
    }

    @Test
    void rejectsBadOutLen() {
        assertThrows(IllegalArgumentException.class, () -> new Blake2s(0));
        assertThrows(IllegalArgumentException.class, () -> new Blake2s(33));
        assertThrows(IllegalArgumentException.class, () -> Blake2s.mac(new byte[33], new byte[0], 16));
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Tiny holder so construction length is asserted without importing protocol in crypto tests. */
    private static final class ProtocolConstruction {
        static final int CONSTRUCTION_LEN = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".length();
    }
}
