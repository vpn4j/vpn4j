package com.github.vpn4j.engine;

import com.github.vpn4j.protocol.ProtocolTimers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionTimersTest {

    @Test
    void keepaliveAfterIdleReceive() {
        ManualClock clock = new ManualClock(1_000_000L);
        SessionTimers timers = new SessionTimers(clock, 0);
        timers.onSessionEstablished(true);
        timers.onReceived();
        assertFalse(timers.wantsKeepalive());
        clock.advance(ProtocolTimers.KEEPALIVE_MS);
        assertTrue(timers.wantsKeepalive());
        timers.onSent();
        assertFalse(timers.wantsKeepalive());
    }

    @Test
    void persistentKeepaliveInterval() {
        ManualClock clock = new ManualClock(0L);
        SessionTimers timers = new SessionTimers(clock, 25);
        timers.onSessionEstablished(false);
        assertFalse(timers.wantsKeepalive());
        clock.advance(25_000L);
        assertTrue(timers.wantsKeepalive());
    }

    @Test
    void rekeyOnlyForInitiatorAfter120s() {
        ManualClock clock = new ManualClock(0L);
        SessionTimers initiator = new SessionTimers(clock, 0);
        initiator.onSessionEstablished(true);
        SessionTimers responder = new SessionTimers(clock, 0);
        responder.onSessionEstablished(false);

        clock.advance(ProtocolTimers.REKEY_AFTER_TIME_MS);
        assertTrue(initiator.wantsRekey());
        assertFalse(responder.wantsRekey());

        initiator.onInitiationAttempt();
        assertFalse(initiator.wantsRekey());
        clock.advance(ProtocolTimers.REKEY_TIMEOUT_MS);
        assertTrue(initiator.wantsRekey());
    }

    @Test
    void rejectAfter180s() {
        ManualClock clock = new ManualClock(0L);
        SessionTimers timers = new SessionTimers(clock, 0);
        timers.onSessionEstablished(true);
        clock.advance(ProtocolTimers.REJECT_AFTER_TIME_MS - 1);
        assertFalse(timers.isRejectedByAge());
        clock.advance(1);
        assertTrue(timers.isRejectedByAge());
    }
}
