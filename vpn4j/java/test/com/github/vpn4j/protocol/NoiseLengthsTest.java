package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NoiseLengthsTest {

    @Test
    void publicProtocolLengths() {
        assertEquals(32, NoiseLengths.PUBLIC_KEY);
        assertEquals(32, NoiseLengths.SYMMETRIC_KEY);
        assertEquals(32, NoiseLengths.HASH);
        assertEquals(16, NoiseLengths.AUTH_TAG);
        assertEquals(12, NoiseLengths.TIMESTAMP);
        assertEquals(16, NoiseLengths.COOKIE);
        assertEquals(24, NoiseLengths.COOKIE_NONCE);
        assertEquals(48, NoiseLengths.encryptedLen(32));
        assertEquals(16, NoiseLengths.encryptedLen(0));
    }
}
