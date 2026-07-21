package com.github.vpn4j.engine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionTimersIdleTest {

    @Test
    void beforeSessionNoActions() {
        ManualClock clock = new ManualClock(0L);
        SessionTimers timers = new SessionTimers(clock, 25);
        assertFalse(timers.wantsKeepalive());
        assertFalse(timers.wantsRekey());
        assertFalse(timers.isRejectedByAge());
        assertFalse(timers.initiator());
    }

    @Test
    void sendResetsIdleKeepalive() {
        ManualClock clock = new ManualClock(0L);
        SessionTimers timers = new SessionTimers(clock, 0);
        timers.onSessionEstablished(true);
        timers.onReceived();
        clock.advance(5_000L);
        timers.onSent();
        clock.advance(5_000L);
        assertFalse(timers.wantsKeepalive());
        clock.advance(10_000L);
        // lastReceived still older than lastSent after the send above... after onSent at 5k,
        // lastReceived was 0, so lastReceived >= lastSent is false → no idle KA.
        assertFalse(timers.wantsKeepalive());
        timers.onReceived();
        clock.advance(10_000L);
        assertTrue(timers.wantsKeepalive());
    }
}
