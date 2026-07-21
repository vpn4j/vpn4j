package com.github.vpn4j.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TransportModeTest {

    @Test
    void values() {
        assertEquals(2, TransportMode.values().length);
        assertEquals(TransportMode.TUN, TransportMode.valueOf("TUN"));
        assertEquals(TransportMode.TCP_TUNNEL, TransportMode.valueOf("TCP_TUNNEL"));
    }
}
