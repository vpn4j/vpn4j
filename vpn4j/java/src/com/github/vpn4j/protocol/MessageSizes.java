package com.github.vpn4j.protocol;

/**
 * Fixed WireGuard message sizes derived from {@link NoiseLengths} (clean-room).
 */
public final class MessageSizes {

    public static final int HEADER = 4;
    public static final int MACS = NoiseLengths.COOKIE * 2;
    public static final int PADDING_MULTIPLE = 16;

    public static final int HANDSHAKE_INITIATION =
            HEADER
                    + 4
                    + NoiseLengths.PUBLIC_KEY
                    + NoiseLengths.encryptedLen(NoiseLengths.PUBLIC_KEY)
                    + NoiseLengths.encryptedLen(NoiseLengths.TIMESTAMP)
                    + MACS;

    public static final int HANDSHAKE_RESPONSE =
            HEADER
                    + 4
                    + 4
                    + NoiseLengths.PUBLIC_KEY
                    + NoiseLengths.encryptedLen(0)
                    + MACS;

    public static final int HANDSHAKE_COOKIE =
            HEADER
                    + 4
                    + NoiseLengths.COOKIE_NONCE
                    + NoiseLengths.encryptedLen(NoiseLengths.COOKIE);

    /** Fixed fields before encrypted payload. */
    public static final int DATA_HEADER = HEADER + 4 + 8;

    public static final int DATA_MINIMUM = DATA_HEADER + NoiseLengths.encryptedLen(0);

    private MessageSizes() {
    }

    public static int dataLen(int plainLen) {
        return DATA_HEADER + NoiseLengths.encryptedLen(plainLen);
    }
}
