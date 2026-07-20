package com.github.vpn4j.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 7539 ChaCha20-Poly1305 AEAD. WireGuard nonce = 32 zero bits || 64-bit LE counter.
 */
public final class ChaCha20Poly1305 {

    private ChaCha20Poly1305() {
    }

    public static byte[] seal(byte[] key, long counter, byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            SecretKey sk = new SecretKeySpec(key, "ChaCha20");
            cipher.init(Cipher.ENCRYPT_MODE, sk, new IvParameterSpec(nonce(counter)));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext == null ? new byte[0] : plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AEAD seal failed", e);
        }
    }

    public static byte[] open(byte[] key, long counter, byte[] ciphertext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            SecretKey sk = new SecretKeySpec(key, "ChaCha20");
            cipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(nonce(counter)));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AEAD open failed", e);
        }
    }

    static byte[] nonce(long counter) {
        byte[] n = new byte[12];
        Bytes.putLongLe(n, 4, counter);
        return n;
    }
}
