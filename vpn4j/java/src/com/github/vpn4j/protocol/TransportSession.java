package com.github.vpn4j.protocol;

import java.util.Objects;

/**
 * One completed Noise session: send/receive data packets with replay protection.
 */
public final class TransportSession {

    /** WireGuard REJECT_AFTER_MESSAGES (approx). */
    public static final long REJECT_AFTER_MESSAGES = Long.MAX_VALUE - ReplayWindow.BITS_TOTAL - 1L;

    private final TransportKeys keys;
    private final ReplayWindow replay = new ReplayWindow();
    private long sendCounter;

    public TransportSession(TransportKeys keys) {
        this.keys = Objects.requireNonNull(keys, "keys");
    }

    public TransportKeys keys() {
        return keys;
    }

    public synchronized byte[] seal(byte[] plaintext) {
        if (sendCounter >= REJECT_AFTER_MESSAGES) {
            throw new IllegalStateException("send counter exhausted");
        }
        long counter = sendCounter++;
        return DataPacket.seal(
                keys.sendingKey().bytes(),
                keys.remoteIndex(),
                counter,
                plaintext);
    }

    /**
     * Open a data packet. Returns plaintext, or {@code null} if replay/old counter.
     */
    public synchronized byte[] open(byte[] packet) {
        DataPacket.Opened opened = DataPacket.open(keys.receivingKey().bytes(), packet);
        if (opened.receiverIndex() != keys.localIndex()) {
            throw new IllegalArgumentException("receiver index mismatch");
        }
        if (opened.counter() >= REJECT_AFTER_MESSAGES) {
            return null;
        }
        if (!replay.tryAccept(opened.counter())) {
            return null;
        }
        return opened.plaintext();
    }

    public synchronized long sendCounter() {
        return sendCounter;
    }
}
