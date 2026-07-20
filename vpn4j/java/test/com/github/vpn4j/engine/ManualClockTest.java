package com.github.vpn4j.engine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManualClockTest {

    @Test
    void advanceAndSet() {
        ManualClock clock = new ManualClock(1000L);
        assertEquals(1000L, clock.millis());
        clock.advance(250L);
        assertEquals(1250L, clock.millis());
        clock.set(50L);
        assertEquals(50L, clock.millis());
    }

    @Test
    void systemClockMoves() {
        NanoClock clock = NanoClock.system();
        long a = clock.millis();
        long b = System.currentTimeMillis();
        assertTrue(Math.abs(a - b) < 5_000L);
    }
}
