package com.github.vpn4j.config;

/**
 * Outer transport for a device. Protocol/crypto is shared; only the wire carrier changes.
 */
public enum TransportMode {
    /** Classic WireGuard-style UDP under a TUN interface. */
    TUN,
    /** Same session model; outer carrier is a TCP tunnel. */
    TCP_TUNNEL
}
