package com.github.vpn4j.transport;

import java.io.Closeable;
import java.io.IOException;
import java.net.SocketAddress;

/**
 * Outer wire carrier for handshake/data datagrams (UDP or TCP tunnel).
 */
public interface PacketCarrier extends Closeable {

    void send(byte[] packet, SocketAddress remote) throws IOException;

    /**
     * Blocking receive into {@code dst}.
     *
     * @return bytes received, or -1 on EOF (TCP)
     */
    int receive(byte[] dst) throws IOException;

    /** Peer address of the last {@link #receive}, or null. */
    SocketAddress lastRemote();
}
