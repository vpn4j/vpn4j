package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class X25519Test {

    @Test
    void sharedSecretIsCommutative() {
        SecureRandom random = new SecureRandom();
        KeyPair a = X25519.generate(random);
        KeyPair b = X25519.generate(random);
        byte[] ab = X25519.sharedSecret(a.privateKey(), b.publicKey());
        byte[] ba = X25519.sharedSecret(b.privateKey(), a.publicKey());
        assertArrayEquals(ab, ba);
        assertEquals(32, ab.length);
        assertFalse(Arrays.equals(ab, new byte[32]));
    }

    @Test
    void publicFromPrivateMatchesGenerated() {
        KeyPair pair = X25519.generate(new SecureRandom());
        Key derived = X25519.publicFromPrivate(pair.privateKey());
        assertArrayEquals(pair.publicKey().bytes(), derived.bytes());
    }
}
