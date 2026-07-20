package com.github.vpn4j.engine;

/**
 * Mutable clock for timer unit tests.
 */
public final class ManualClock implements NanoClock {

    private long millis;

    public ManualClock(long startMillis) {
        this.millis = startMillis;
    }

    @Override
    public long millis() {
        return millis;
    }

    public void advance(long deltaMs) {
        millis += deltaMs;
    }

    public void set(long millis) {
        this.millis = millis;
    }
}
