package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeysTest {

    @Test
    void base64RoundTripAndTrim() {
        byte[] raw = new byte[32];
        Arrays.fill(raw, (byte) 0x5a);
        Key key = new Key(raw);
        String b64 = Keys.toBase64(key);
        assertTrue(Keys.fromBase64("  " + b64 + "\n").equalsConstantTime(key));
        assertArrayEquals(raw, Keys.fromBase64(b64).bytes());
    }

    @Test
    void fromBase64RejectsWrongDecodedLength() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);
        assertThrows(IllegalArgumentException.class, () -> Keys.fromBase64(shortKey));
    }

    @Test
    void fromBase64RejectsInvalidAlphabet() {
        assertThrows(IllegalArgumentException.class, () -> Keys.fromBase64("!!!not-base64!!!"));
    }

    @Test
    void keyPairFromPrivateMatchesX25519() {
        byte[] priv = new byte[32];
        for (int i = 0; i < 32; i++) {
            priv[i] = (byte) i;
        }
        KeyPair pair = Keys.keyPairFromPrivate(new Key(priv));
        byte[] clamped = priv.clone();
        KeyPair.clampCurve25519(clamped);
        assertArrayEquals(clamped, pair.privateKey().bytes());
        assertTrue(pair.publicKey().equalsConstantTime(X25519.publicFromPrivate(new Key(clamped))));
    }
}
