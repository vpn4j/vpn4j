package com.github.vpn4j.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Paired in-memory carriers for peer-engine tests (no real UDP/TCP).
 */
public final class InMemoryCarrierPair {

    private final BlockingQueue<byte[]> aToB = new LinkedBlockingQueue<>();
    private final BlockingQueue<byte[]> bToA = new LinkedBlockingQueue<>();
    private final SocketAddress addrA = new InetSocketAddress("127.0.0.1", 1);
    private final SocketAddress addrB = new InetSocketAddress("127.0.0.1", 2);

    public PacketCarrier sideA() {
        return new Side(aToB, bToA, addrB);
    }

    public PacketCarrier sideB() {
        return new Side(bToA, aToB, addrA);
    }

    private static final class Side implements PacketCarrier {
        private final BlockingQueue<byte[]> out;
        private final BlockingQueue<byte[]> in;
        private final SocketAddress peer;
        private SocketAddress lastRemote;
        private volatile boolean closed;

        Side(BlockingQueue<byte[]> out, BlockingQueue<byte[]> in, SocketAddress peer) {
            this.out = out;
            this.in = in;
            this.peer = peer;
        }

        @Override
        public void send(byte[] packet, SocketAddress remote) throws IOException {
            ensureOpen();
            out.offer(packet.clone());
        }

        @Override
        public int receive(byte[] dst) throws IOException {
            ensureOpen();
            try {
                byte[] pkt = in.poll(50, TimeUnit.MILLISECONDS);
                if (pkt == null) {
                    return 0;
                }
                if (pkt.length > dst.length) {
                    throw new IOException("receive buffer too small");
                }
                System.arraycopy(pkt, 0, dst, 0, pkt.length);
                lastRemote = peer;
                return pkt.length;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("receive interrupted", e);
            }
        }

        @Override
        public SocketAddress lastRemote() {
            return lastRemote;
        }

        @Override
        public void close() {
            closed = true;
        }

        private void ensureOpen() throws IOException {
            if (closed) {
                throw new IOException("carrier closed");
            }
        }
    }
}
