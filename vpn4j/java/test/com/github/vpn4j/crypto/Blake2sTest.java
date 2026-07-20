package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

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
