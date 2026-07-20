package com.github.vpn4j.crypto;

import com.github.vpn4j.testsupport.Hex;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XChaCha20Poly1305Test {

    @Test
    void draftIrtfCfrgXchachaAppendixA1() {
        // draft-irtf-cfrg-xchacha-03 Appendix A.1
        byte[] key = Hex.decode(
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce24 = Hex.decode("404142434445464748494a4b4c4d4e4f5051525354555657");
        byte[] aad = Hex.decode("50515253c0c1c2c3c4c5c6c7");
        byte[] plaintext =
                "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                        .getBytes(StandardCharsets.US_ASCII);
        byte[] expectedCt = Hex.decode(
                "bd6d179d3e83d43b9576579493c0e939"
                        + "572a1700252bfaccbed2902c21396cbb"
                        + "731c7f1b0b4aa6440bf3a82f4eda7e39"
                        + "ae64c6708c54c216cb96b72e1213b452"
                        + "2f8c9ba40db5d945b11b69b982c1bb9e"
                        + "3f3fac2bc369488f76b2383565d3fff9"
                        + "21f9664c97637da9768812f615c68b13"
                        + "b52e"
                        + "c0875924c1c7987947deafd8780acf49");

        byte[] sealed = XChaCha20Poly1305.seal(key, nonce24, plaintext, aad);
        assertArrayEquals(expectedCt, sealed);
        assertArrayEquals(plaintext, XChaCha20Poly1305.open(key, nonce24, sealed, aad));
    }

    @Test
    void roundTripEmptyPlaintextAndNullAad() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 3);
        byte[] nonce = new byte[24];
        Arrays.fill(nonce, (byte) 9);
        byte[] sealed = XChaCha20Poly1305.seal(key, nonce, null, null);
        assertEquals(16, sealed.length);
        assertArrayEquals(new byte[0], XChaCha20Poly1305.open(key, nonce, sealed, null));
    }

    @Test
    void rejectsBadKeyOrNonceLength() {
        assertThrows(
                IllegalArgumentException.class,
                () -> XChaCha20Poly1305.seal(new byte[31], new byte[24], new byte[0], null));
        assertThrows(
                IllegalArgumentException.class,
                () -> XChaCha20Poly1305.seal(new byte[32], new byte[23], new byte[0], null));
    }

    @Test
    void openFailsOnTamperOrWrongAad() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        byte[] aad = new byte[] {1, 2, 3};
        byte[] sealed = XChaCha20Poly1305.seal(key, nonce, new byte[] {7}, aad);
        sealed[0] ^= 1;
        assertThrows(IllegalStateException.class, () -> XChaCha20Poly1305.open(key, nonce, sealed, aad));

        byte[] sealed2 = XChaCha20Poly1305.seal(key, nonce, new byte[] {7}, aad);
        assertThrows(
                IllegalStateException.class,
                () -> XChaCha20Poly1305.open(key, nonce, sealed2, new byte[] {9}));
    }
}
