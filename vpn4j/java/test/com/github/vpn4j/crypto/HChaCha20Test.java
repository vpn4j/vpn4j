package com.github.vpn4j.crypto;

import com.github.vpn4j.testsupport.Hex;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HChaCha20Test {

    @Test
    void draftIrtfCfrgXchachaSection221() {
        // draft-irtf-cfrg-xchacha-03 §2.2.1
        byte[] key = Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce16 = Hex.decode("000000090000004a0000000031415927");
        byte[] expected = Hex.decode(
                "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
        assertArrayEquals(expected, HChaCha20.derive(key, nonce16));
    }

    @Test
    void rejectsBadLengths() {
        assertThrows(IllegalArgumentException.class, () -> HChaCha20.derive(new byte[31], new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> HChaCha20.derive(new byte[32], new byte[15]));
    }
}
