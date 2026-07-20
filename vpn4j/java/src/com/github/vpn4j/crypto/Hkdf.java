package com.github.vpn4j.crypto;

/**
 * HKDF with HMAC-BLAKE2s as used by WireGuard / Noise (KDF1/2/3).
 */
public final class Hkdf {

    private Hkdf() {
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        // HMAC(K, m) with BLAKE2s-256 as hash (block 64)
        byte[] keyBlock = new byte[64];
        if (key.length > 64) {
            byte[] hashed = Blake2s.hash32(key);
            System.arraycopy(hashed, 0, keyBlock, 0, hashed.length);
        } else {
            System.arraycopy(key, 0, keyBlock, 0, key.length);
        }
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];
        for (int i = 0; i < 64; i++) {
            ipad[i] = (byte) (keyBlock[i] ^ 0x36);
            opad[i] = (byte) (keyBlock[i] ^ 0x5c);
        }
        Blake2s inner = new Blake2s(32);
        inner.update(ipad, 0, 64);
        inner.update(data, 0, data.length);
        byte[] innerHash = inner.digest();
        Blake2s outer = new Blake2s(32);
        outer.update(opad, 0, 64);
        outer.update(innerHash, 0, innerHash.length);
        return outer.digest();
    }

    /** KDF1: returns new chaining key. */
    public static byte[] kdf1(byte[] chainingKey, byte[] input) {
        byte[] temp = hmac(chainingKey, input);
        return hmac(temp, new byte[] {0x01});
    }

    /** KDF2: returns [chainingKey, key]. */
    public static byte[][] kdf2(byte[] chainingKey, byte[] input) {
        byte[] temp = hmac(chainingKey, input);
        byte[] out1 = hmac(temp, new byte[] {0x01});
        byte[] out2 = hmac(temp, Bytes.concat(out1, new byte[] {0x02}));
        return new byte[][] {out1, out2};
    }

    /** KDF3: returns [chainingKey, mid, key]. */
    public static byte[][] kdf3(byte[] chainingKey, byte[] input) {
        byte[] temp = hmac(chainingKey, input);
        byte[] out1 = hmac(temp, new byte[] {0x01});
        byte[] out2 = hmac(temp, Bytes.concat(out1, new byte[] {0x02}));
        byte[] out3 = hmac(temp, Bytes.concat(out2, new byte[] {0x03}));
        return new byte[][] {out1, out2, out3};
    }
}
