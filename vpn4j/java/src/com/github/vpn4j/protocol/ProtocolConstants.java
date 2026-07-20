package com.github.vpn4j.protocol;

import java.nio.charset.StandardCharsets;

/**
 * Public WireGuard protocol string constants (from wireguard.com/protocol).
 */
public final class ProtocolConstants {

    public static final byte[] CONSTRUCTION =
            "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes(StandardCharsets.UTF_8);

    public static final byte[] IDENTIFIER =
            "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes(StandardCharsets.UTF_8);

    public static final byte[] LABEL_MAC1 = "mac1----".getBytes(StandardCharsets.UTF_8);

    public static final byte[] LABEL_COOKIE = "cookie--".getBytes(StandardCharsets.UTF_8);

    private ProtocolConstants() {
    }
}
