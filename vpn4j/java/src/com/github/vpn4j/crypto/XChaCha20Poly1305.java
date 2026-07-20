package com.github.vpn4j.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * XChaCha20-Poly1305 AEAD (24-byte nonce) via HChaCha20 + JDK ChaCha20-Poly1305.
 */
public final class XChaCha20Poly1305 {

    private XChaCha20Poly1305() {
    }

    public static byte[] seal(byte[] key32, byte[] nonce24, byte[] plaintext, byte[] aad) {
        return crypt(Cipher.ENCRYPT_MODE, key32, nonce24, plaintext, aad);
    }

    public static byte[] open(byte[] key32, byte[] nonce24, byte[] ciphertext, byte[] aad) {
        return crypt(Cipher.DECRYPT_MODE, key32, nonce24, ciphertext, aad);
    }

    private static byte[] crypt(int mode, byte[] key32, byte[] nonce24, byte[] input, byte[] aad) {
        if (key32.length != 32 || nonce24.length != 24) {
            throw new IllegalArgumentException("XChaCha20-Poly1305 needs 32-byte key and 24-byte nonce");
        }
        byte[] subkey = HChaCha20.derive(key32, Arrays.copyOfRange(nonce24, 0, 16));
        byte[] nonce12 = new byte[12];
        System.arraycopy(nonce24, 16, nonce12, 4, 8);
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            SecretKey sk = new SecretKeySpec(subkey, "ChaCha20");
            cipher.init(mode, sk, new IvParameterSpec(nonce12));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(input == null ? new byte[0] : input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("XAEAD failed", e);
        }
    }
}
