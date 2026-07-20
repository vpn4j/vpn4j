package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ProtocolConstantsTest {

    @Test
    void wireGuardPublicStrings() {
        assertArrayEquals(
                "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes(StandardCharsets.UTF_8),
                ProtocolConstants.CONSTRUCTION);
        assertEquals(37, ProtocolConstants.CONSTRUCTION.length);

        assertArrayEquals(
                "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes(StandardCharsets.UTF_8),
                ProtocolConstants.IDENTIFIER);
        assertEquals(34, ProtocolConstants.IDENTIFIER.length);

        assertArrayEquals("mac1----".getBytes(StandardCharsets.UTF_8), ProtocolConstants.LABEL_MAC1);
        assertArrayEquals("cookie--".getBytes(StandardCharsets.UTF_8), ProtocolConstants.LABEL_COOKIE);
        assertEquals(8, ProtocolConstants.LABEL_MAC1.length);
        assertEquals(8, ProtocolConstants.LABEL_COOKIE.length);
    }

    @Test
    void timerConstantsMatchPublicProtocol() {
        assertEquals(10_000L, ProtocolTimers.KEEPALIVE_MS);
        assertEquals(120_000L, ProtocolTimers.REKEY_AFTER_TIME_MS);
        assertEquals(180_000L, ProtocolTimers.REJECT_AFTER_TIME_MS);
        assertEquals(5_000L, ProtocolTimers.REKEY_TIMEOUT_MS);
    }
}
