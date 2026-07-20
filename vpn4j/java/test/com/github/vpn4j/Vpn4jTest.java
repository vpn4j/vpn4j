package com.github.vpn4j;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class Vpn4jTest {

    @Test
    void version() {
        assertEquals("1.0.0-SNAPSHOT", Vpn4j.version());
    }
}
