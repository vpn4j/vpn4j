package com.github.vpn4j.crypto;

import java.util.Base64;

/**
 * WireGuard-style base64 key helpers (32-byte keys).
 */
public final class Keys {

    private Keys() {
    }

    public static Key fromBase64(String base64) {
        byte[] raw = Base64.getDecoder().decode(base64.trim());
        if (raw.length != 32) {
            throw new IllegalArgumentException("key must decode to 32 bytes");
        }
        return new Key(raw);
    }

    public static String toBase64(Key key) {
        return Base64.getEncoder().encodeToString(key.bytes());
    }

    public static KeyPair keyPairFromPrivate(Key privateKey) {
        byte[] priv = privateKey.bytes();
        KeyPair.clampCurve25519(priv);
        Key clamped = new Key(priv);
        Key pub = X25519.publicFromPrivate(clamped);
        return new KeyPair(clamped, pub);
    }
}
