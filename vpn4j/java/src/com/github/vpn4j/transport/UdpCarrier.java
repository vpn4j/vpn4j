package com.github.vpn4j.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

/**
 * Classic WireGuard-style UDP carrier.
 */
public final class UdpCarrier implements PacketCarrier {

    private final DatagramChannel channel;
    private SocketAddress lastRemote;

    public UdpCarrier(DatagramChannel channel) {
        this.channel = channel;
    }

    public static UdpCarrier bind(int listenPort) throws IOException {
        DatagramChannel ch = DatagramChannel.open();
        ch.setOption(StandardSocketOptions.SO_REUSEADDR, Boolean.TRUE);
        ch.configureBlocking(false);
        ch.bind(new InetSocketAddress(listenPort));
        return new UdpCarrier(ch);
    }

    public DatagramChannel channel() {
        return channel;
    }

    @Override
    public void send(byte[] packet, SocketAddress remote) throws IOException {
        channel.send(ByteBuffer.wrap(packet), remote);
    }

    @Override
    public int receive(byte[] dst) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(dst);
        SocketAddress remote = channel.receive(buf);
        if (remote == null) {
            return 0;
        }
        lastRemote = remote;
        return buf.position();
    }

    @Override
    public SocketAddress lastRemote() {
        return lastRemote;
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
