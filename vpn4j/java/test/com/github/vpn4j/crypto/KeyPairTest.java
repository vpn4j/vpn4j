package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyPairTest {

    @Test
    void clampClearsAndSetsBits() {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) 0xFF;
        }
        KeyPair.clampCurve25519(key);
        assertEquals(0, key[0] & 0x07);
        assertEquals(0x40, key[31] & 0xC0);
    }

    @Test
    void generateHasUsableKeyLengths() {
        KeyPair pair = KeyPair.generate(new SecureRandom());
        assertEquals(32, pair.privateKey().length());
        assertEquals(32, pair.publicKey().length());
        assertTrue(pair.publicKey().bytes()[0] != 0 || pair.publicKey().bytes()[1] != 0);
    }
}
