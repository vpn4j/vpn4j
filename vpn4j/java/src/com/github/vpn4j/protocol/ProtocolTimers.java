package com.github.vpn4j.protocol;

/**
 * WireGuard timer constants (public protocol), in milliseconds.
 */
public final class ProtocolTimers {

    public static final long KEEPALIVE_MS = 10_000L;
    public static final long REKEY_AFTER_TIME_MS = 120_000L;
    public static final long REJECT_AFTER_TIME_MS = 180_000L;
    public static final long REKEY_TIMEOUT_MS = 5_000L;

    private ProtocolTimers() {
    }
}
