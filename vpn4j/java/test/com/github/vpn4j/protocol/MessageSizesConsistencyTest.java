package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MessageSizesConsistencyTest {

    @Test
    void sizesDeriveFromNoiseLengths() {
        assertEquals(
                MessageSizes.HEADER
                        + 4
                        + NoiseLengths.PUBLIC_KEY
                        + NoiseLengths.encryptedLen(NoiseLengths.PUBLIC_KEY)
                        + NoiseLengths.encryptedLen(NoiseLengths.TIMESTAMP)
                        + MessageSizes.MACS,
                MessageSizes.HANDSHAKE_INITIATION);
        assertEquals(
                MessageSizes.HEADER
                        + 4
                        + 4
                        + NoiseLengths.PUBLIC_KEY
                        + NoiseLengths.encryptedLen(0)
                        + MessageSizes.MACS,
                MessageSizes.HANDSHAKE_RESPONSE);
        assertEquals(
                MessageSizes.HEADER
                        + 4
                        + NoiseLengths.COOKIE_NONCE
                        + NoiseLengths.encryptedLen(NoiseLengths.COOKIE),
                MessageSizes.HANDSHAKE_COOKIE);
        assertEquals(MessageSizes.DATA_HEADER + NoiseLengths.encryptedLen(0), MessageSizes.DATA_MINIMUM);
        assertEquals(NoiseLengths.COOKIE * 2, MessageSizes.MACS);
    }
}
