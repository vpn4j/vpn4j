package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MessageSizesTest {

    @Test
    void wireSizesMatchPublicProtocol() {
        assertEquals(148, MessageSizes.HANDSHAKE_INITIATION);
        assertEquals(92, MessageSizes.HANDSHAKE_RESPONSE);
        assertEquals(64, MessageSizes.HANDSHAKE_COOKIE);
        assertEquals(16, MessageSizes.DATA_HEADER);
        assertEquals(32, MessageSizes.DATA_MINIMUM);
    }

    @Test
    void dataLenIncludesPayloadAndTag() {
        assertEquals(MessageSizes.DATA_MINIMUM + 64, MessageSizes.dataLen(64));
    }
}
