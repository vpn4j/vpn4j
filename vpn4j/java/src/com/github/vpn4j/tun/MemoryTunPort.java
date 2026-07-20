package com.github.vpn4j.tun;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * In-memory TUN for engine tests (no CAP_NET_ADMIN).
 */
public final class MemoryTunPort implements TunPort {

    private final BlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>();
    private final BlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
    private volatile boolean closed;

    /** Inject a packet as if the OS delivered it from the TUN. */
    public void injectFromOs(byte[] packet) {
        ensureOpen();
        inbound.offer(packet.clone());
    }

    /** Packet the engine wrote toward the OS (decrypted inbound). */
    public byte[] pollToOs(long timeoutMs) throws InterruptedException {
        return outbound.poll(timeoutMs, TimeUnit.MILLISECONDS);
    }

    @Override
    public int read(byte[] dst, int offset, int length) {
        ensureOpen();
        byte[] pkt = inbound.poll();
        if (pkt == null) {
            return 0;
        }
        int n = Math.min(length, pkt.length);
        System.arraycopy(pkt, 0, dst, offset, n);
        return n;
    }

    @Override
    public void write(byte[] src, int offset, int length) {
        ensureOpen();
        byte[] pkt = new byte[length];
        System.arraycopy(src, offset, pkt, 0, length);
        outbound.offer(pkt);
    }

    @Override
    public void close() {
        closed = true;
        inbound.clear();
        outbound.clear();
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("MemoryTunPort closed");
        }
    }
}
