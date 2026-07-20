package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReplayWindowTest {

    @Test
    void acceptsInOrderAndRejectsReplay() {
        ReplayWindow window = new ReplayWindow();
        assertTrue(window.tryAccept(0));
        assertTrue(window.tryAccept(1));
        assertTrue(window.tryAccept(2));
        assertFalse(window.tryAccept(1));
        assertFalse(window.tryAccept(2));
        assertEquals(2L, window.latest());
    }

    @Test
    void acceptsOutOfOrderWithinWindow() {
        ReplayWindow window = new ReplayWindow();
        assertTrue(window.tryAccept(5));
        assertTrue(window.tryAccept(3));
        assertTrue(window.tryAccept(4));
        assertFalse(window.tryAccept(3));
        assertTrue(window.tryAccept(6));
    }

    @Test
    void rejectsTooOld() {
        ReplayWindow window = new ReplayWindow();
        assertTrue(window.tryAccept(ReplayWindow.BITS_TOTAL + 10L));
        assertFalse(window.tryAccept(10L));
    }

    @Test
    void rejectsNegativeAndClearsOnHugeJump() {
        ReplayWindow window = new ReplayWindow();
        assertFalse(window.tryAccept(-1L));
        assertTrue(window.tryAccept(100L));
        assertTrue(window.tryAccept(100L + ReplayWindow.BITS_TOTAL));
        assertEquals(100L + ReplayWindow.BITS_TOTAL, window.latest());
        // prior counters wiped by clear on huge jump
        assertFalse(window.tryAccept(100L));
    }
}
