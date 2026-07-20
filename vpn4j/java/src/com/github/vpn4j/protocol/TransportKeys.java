package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Key;

/**
 * Post-handshake sending/receiving keys for one role.
 */
public final class TransportKeys {

    private final Key sendingKey;
    private final Key receivingKey;
    private final int localIndex;
    private final int remoteIndex;

    public TransportKeys(Key sendingKey, Key receivingKey, int localIndex, int remoteIndex) {
        this.sendingKey = sendingKey;
        this.receivingKey = receivingKey;
        this.localIndex = localIndex;
        this.remoteIndex = remoteIndex;
    }

    public Key sendingKey() {
        return sendingKey;
    }

    public Key receivingKey() {
        return receivingKey;
    }

    public int localIndex() {
        return localIndex;
    }

    public int remoteIndex() {
        return remoteIndex;
    }
}
