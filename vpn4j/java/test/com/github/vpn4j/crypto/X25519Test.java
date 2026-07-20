package com.github.vpn4j.crypto;

import com.github.vpn4j.testsupport.Hex;

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

    @Test
    void rfc7748Section61() {
        // RFC 7748 §6.1
        Key alicePriv = new Key(Hex.decode(
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        Key bobPriv = new Key(Hex.decode(
                "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
        Key alicePub = HexKey(
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        Key bobPub = HexKey(
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] shared = Hex.decode(
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assertArrayEquals(alicePub.bytes(), X25519.publicFromPrivate(alicePriv).bytes());
        assertArrayEquals(bobPub.bytes(), X25519.publicFromPrivate(bobPriv).bytes());
        assertArrayEquals(shared, X25519.sharedSecret(alicePriv, bobPub));
        assertArrayEquals(shared, X25519.sharedSecret(bobPriv, alicePub));
    }

    private static Key HexKey(String hex) {
        return new Key(Hex.decode(hex));
    }
}
