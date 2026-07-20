package com.github.vpn4j.transport;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.Objects;

/**
 * TCP tunnel carrier: each WG datagram framed as {@code u32be length || bytes}.
 *
 * <p>Same Noise/data packets as UDP; only the outer transport differs.
 */
public final class TcpTunnelCarrier implements PacketCarrier {

    private final Socket socket;
    private final DataInputStream in;
    private final DataOutputStream out;
    private final SocketAddress remote;

    public TcpTunnelCarrier(Socket socket) throws IOException {
        this.socket = Objects.requireNonNull(socket, "socket");
        this.remote = socket.getRemoteSocketAddress();
        InputStream rawIn = socket.getInputStream();
        OutputStream rawOut = socket.getOutputStream();
        this.in = new DataInputStream(rawIn);
        this.out = new DataOutputStream(rawOut);
    }

    public static TcpTunnelCarrier connect(String host, int port) throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(host, port));
        return new TcpTunnelCarrier(socket);
    }

    public static TcpTunnelCarrier wrap(Socket accepted) throws IOException {
        return new TcpTunnelCarrier(accepted);
    }

    @Override
    public void send(byte[] packet, SocketAddress ignored) throws IOException {
        out.writeInt(packet.length);
        out.write(packet);
        out.flush();
    }

    @Override
    public int receive(byte[] dst) throws IOException {
        int len;
        try {
            len = in.readInt();
        } catch (IOException e) {
            return -1;
        }
        if (len < 0 || len > dst.length) {
            throw new IOException("tcp tunnel frame length invalid: " + len);
        }
        in.readFully(dst, 0, len);
        return len;
    }

    @Override
    public SocketAddress lastRemote() {
        return remote;
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
