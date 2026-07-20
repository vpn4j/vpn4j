package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PacketPaddingTest {

    @Test
    void emptyUnchanged() {
        assertEquals(0, PacketPadding.pad(new byte[0]).length);
    }

    @Test
    void padsToMultipleOf16() {
        assertEquals(16, PacketPadding.pad(new byte[1]).length);
        assertEquals(16, PacketPadding.pad(new byte[16]).length);
        assertEquals(32, PacketPadding.pad(new byte[17]).length);
    }
}
