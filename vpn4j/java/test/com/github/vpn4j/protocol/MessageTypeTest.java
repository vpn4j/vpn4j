package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MessageTypeTest {

    @Test
    void wireRoundTrip() {
        assertEquals(1, MessageType.HANDSHAKE_INITIATION.wire());
        assertEquals(2, MessageType.HANDSHAKE_RESPONSE.wire());
        assertEquals(3, MessageType.HANDSHAKE_COOKIE.wire());
        assertEquals(4, MessageType.DATA.wire());
        assertEquals(MessageType.HANDSHAKE_INITIATION, MessageType.fromWire(1));
        assertEquals(MessageType.HANDSHAKE_RESPONSE, MessageType.fromWire(2));
        assertEquals(MessageType.HANDSHAKE_COOKIE, MessageType.fromWire(3));
        assertEquals(MessageType.DATA, MessageType.fromWire(4));
        assertEquals(MessageType.INVALID, MessageType.fromWire(0));
        assertEquals(MessageType.INVALID, MessageType.fromWire(5));
        assertEquals(MessageType.INVALID, MessageType.fromWire(255));
    }
}
