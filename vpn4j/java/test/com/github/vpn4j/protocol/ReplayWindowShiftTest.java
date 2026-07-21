package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReplayWindowShiftTest {

    @Test
    void multiWordShiftKeepsRecentBits() {
        ReplayWindow window = new ReplayWindow();
        assertTrue(window.tryAccept(0));
        assertTrue(window.tryAccept(1));
        // Jump by more than 64 bits to exercise word-shifting path
        assertTrue(window.tryAccept(100));
        assertFalse(window.tryAccept(1)); // shifted out / replay
        assertTrue(window.tryAccept(99));
        assertFalse(window.tryAccept(99));
    }
}
