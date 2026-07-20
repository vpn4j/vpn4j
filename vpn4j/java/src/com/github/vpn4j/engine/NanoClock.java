package com.github.vpn4j.engine;

/**
 * Injectable clock for keepalive/rekey tests.
 */
public interface NanoClock {

    long millis();

    static NanoClock system() {
        return System::currentTimeMillis;
    }
}
