package com.github.vpn4j.engine;

import com.github.vpn4j.protocol.ProtocolTimers;

/**
 * Keepalive / rekey / reject scheduling for one transport session.
 */
public final class SessionTimers {

    private final NanoClock clock;
    private final int persistentKeepaliveSeconds;
    private long sessionStartedMs = -1L;
    private long lastSentMs = -1L;
    private long lastReceivedMs = -1L;
    private boolean initiator;
    private long lastInitiationAttemptMs = -1L;

    public SessionTimers(NanoClock clock, int persistentKeepaliveSeconds) {
        this.clock = clock;
        this.persistentKeepaliveSeconds = Math.max(0, persistentKeepaliveSeconds);
    }

    public void onSessionEstablished(boolean initiator) {
        long now = clock.millis();
        this.initiator = initiator;
        this.sessionStartedMs = now;
        this.lastSentMs = now;
        this.lastReceivedMs = now;
    }

    public void onSent() {
        lastSentMs = clock.millis();
    }

    public void onReceived() {
        lastReceivedMs = clock.millis();
    }

    public void onInitiationAttempt() {
        lastInitiationAttemptMs = clock.millis();
    }

    public boolean wantsKeepalive() {
        if (sessionStartedMs < 0L) {
            return false;
        }
        long now = clock.millis();
        if (persistentKeepaliveSeconds > 0) {
            return now - lastSentMs >= persistentKeepaliveSeconds * 1000L;
        }
        // Received traffic and have not sent back within KEEPALIVE.
        return lastReceivedMs >= 0L
                && lastReceivedMs >= lastSentMs
                && now - lastSentMs >= ProtocolTimers.KEEPALIVE_MS;
    }

    /** Initiator should rekey after REKEY_AFTER_TIME. */
    public boolean wantsRekey() {
        if (sessionStartedMs < 0L || !initiator) {
            return false;
        }
        long now = clock.millis();
        if (now - sessionStartedMs < ProtocolTimers.REKEY_AFTER_TIME_MS) {
            return false;
        }
        if (lastInitiationAttemptMs >= 0L
                && now - lastInitiationAttemptMs < ProtocolTimers.REKEY_TIMEOUT_MS) {
            return false;
        }
        return true;
    }

    public boolean isRejectedByAge() {
        if (sessionStartedMs < 0L) {
            return false;
        }
        return clock.millis() - sessionStartedMs >= ProtocolTimers.REJECT_AFTER_TIME_MS;
    }

    public boolean initiator() {
        return initiator;
    }
}
