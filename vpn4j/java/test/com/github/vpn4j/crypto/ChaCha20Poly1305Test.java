package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ChaCha20Poly1305Test {

    @Test
    void roundTripWithAad() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);
        byte[] plain = "vpn4j-aead".getBytes();
        byte[] aad = new byte[32];
        Arrays.fill(aad, (byte) 1);
        byte[] sealed = ChaCha20Poly1305.seal(key, 0L, plain, aad);
        assertEquals(plain.length + 16, sealed.length);
        byte[] opened = ChaCha20Poly1305.open(key, 0L, sealed, aad);
        assertArrayEquals(plain, opened);
    }

    @Test
    void wireGuardNonceLayout() {
        // WireGuard: 32 zero bits || 64-bit little-endian counter
        assertArrayEquals(new byte[12], ChaCha20Poly1305.nonce(0L));
        byte[] n = ChaCha20Poly1305.nonce(0x0807060504030201L);
        assertEquals(0, n[0]);
        assertEquals(0, n[1]);
        assertEquals(0, n[2]);
        assertEquals(0, n[3]);
        assertEquals(0x01, n[4] & 0xff);
        assertEquals(0x08, n[11] & 0xff);
    }

    @Test
    void emptyPlaintextAndDifferentCounters() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 2);
        byte[] empty = ChaCha20Poly1305.seal(key, 0L, null, null);
        assertEquals(16, empty.length);
        assertArrayEquals(new byte[0], ChaCha20Poly1305.open(key, 0L, empty, null));

        byte[] c0 = ChaCha20Poly1305.seal(key, 0L, new byte[] {1}, new byte[0]);
        byte[] c1 = ChaCha20Poly1305.seal(key, 1L, new byte[] {1}, new byte[0]);
        assertFalse(Arrays.equals(c0, c1));
    }

    @Test
    void openFailsOnWrongAadOrTamper() {
        byte[] key = new byte[32];
        byte[] aad = new byte[] {1, 2, 3};
        byte[] sealed = ChaCha20Poly1305.seal(key, 5L, new byte[] {9}, aad);
        assertThrows(IllegalStateException.class, () -> ChaCha20Poly1305.open(key, 5L, sealed, new byte[] {0}));
        sealed[0] ^= 0xff;
        assertThrows(IllegalStateException.class, () -> ChaCha20Poly1305.open(key, 5L, sealed, aad));
    }
}
