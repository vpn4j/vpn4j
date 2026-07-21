package com.github.vpn4j.transport;

import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TcpTunnelCarrierTest {

    @Test
    void framedRoundTrip() throws Exception {
        ArrayBlockingQueue<byte[]> received = new ArrayBlockingQueue<>(1);
        ServerSocket server = new ServerSocket(0);
        Thread acceptor = new Thread(new AcceptAndEcho(server, received));
        acceptor.setDaemon(true);
        acceptor.start();

        try (TcpTunnelCarrier client = TcpTunnelCarrier.connect("127.0.0.1", server.getLocalPort())) {
            byte[] payload = "framed".getBytes(StandardCharsets.US_ASCII);
            client.send(payload, null);
            byte[] echo = received.poll(5, TimeUnit.SECONDS);
            assertArrayEquals(payload, echo);

            byte[] dst = new byte[64];
            int n = client.receive(dst);
            assertEquals(payload.length, n);
            byte[] got = new byte[n];
            System.arraycopy(dst, 0, got, 0, n);
            assertArrayEquals(payload, got);
            org.junit.jupiter.api.Assertions.assertNotNull(client.lastRemote());
        } finally {
            server.close();
            acceptor.join(2000);
        }
    }

    private static final class AcceptAndEcho implements Runnable {
        private final ServerSocket server;
        private final ArrayBlockingQueue<byte[]> received;

        AcceptAndEcho(ServerSocket server, ArrayBlockingQueue<byte[]> received) {
            this.server = server;
            this.received = received;
        }

        @Override
        public void run() {
            try (Socket socket = server.accept();
                    TcpTunnelCarrier carrier = TcpTunnelCarrier.wrap(socket)) {
                byte[] dst = new byte[256];
                int n = carrier.receive(dst);
                byte[] msg = new byte[n];
                System.arraycopy(dst, 0, msg, 0, n);
                received.offer(msg);
                carrier.send(msg, null);
            } catch (Exception ignored) {
                // test teardown
            }
        }
    }
}
