package com.github.vpn4j.protocol;

/**
 * Noise / WireGuard-compatible length constants (clean-room from public protocol).
 */
public final class NoiseLengths {

    public static final int PUBLIC_KEY = 32;
    public static final int SYMMETRIC_KEY = 32;
    public static final int HASH = 32;
    public static final int AUTH_TAG = 16;
    public static final int TIMESTAMP = 12;
    public static final int COOKIE = 16;
    public static final int COOKIE_NONCE = 24;

    private NoiseLengths() {
    }

    public static int encryptedLen(int plainLen) {
        return plainLen + AUTH_TAG;
    }
}
