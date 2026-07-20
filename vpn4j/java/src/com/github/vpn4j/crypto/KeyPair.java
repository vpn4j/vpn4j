package com.github.vpn4j.crypto;

import java.security.SecureRandom;

/**
 * Curve25519 / X25519 keypair.
 */
public final class KeyPair {

    private final Key privateKey;
    private final Key publicKey;

    public KeyPair(Key privateKey, Key publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public Key privateKey() {
        return privateKey;
    }

    public Key publicKey() {
        return publicKey;
    }

    public static KeyPair generate(SecureRandom random) {
        return X25519.generate(random);
    }

    /** @deprecated use {@link #generate(SecureRandom)} */
    public static KeyPair generateEphemeral(SecureRandom random) {
        return generate(random);
    }

    /** Curve25519 private-key clamping (public algorithm). */
    public static void clampCurve25519(byte[] privateKey) {
        if (privateKey.length != 32) {
            throw new IllegalArgumentException("private key must be 32 bytes");
        }
        privateKey[0] &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;
    }
}
