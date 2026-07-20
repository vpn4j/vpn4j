package com.github.vpn4j.protocol;

/**
 * WireGuard message type byte (little-endian u32 low byte on the wire).
 */
public enum MessageType {
    INVALID(0),
    HANDSHAKE_INITIATION(1),
    HANDSHAKE_RESPONSE(2),
    HANDSHAKE_COOKIE(3),
    DATA(4);

    private final int wire;

    MessageType(int wire) {
        this.wire = wire;
    }

    public int wire() {
        return wire;
    }

    public static MessageType fromWire(int value) {
        switch (value) {
            case 1:
                return HANDSHAKE_INITIATION;
            case 2:
                return HANDSHAKE_RESPONSE;
            case 3:
                return HANDSHAKE_COOKIE;
            case 4:
                return DATA;
            default:
                return INVALID;
        }
    }
}
