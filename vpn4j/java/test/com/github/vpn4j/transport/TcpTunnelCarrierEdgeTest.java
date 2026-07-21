package com.github.vpn4j.transport;

import org.junit.jupiter.api.Test;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TcpTunnelCarrierEdgeTest {

    @Test
    void invalidFrameLengthAndEof() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        ServerSocket server = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            try (Socket socket = server.accept();
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
                ready.countDown();
                // Oversized length relative to client buffer
                out.writeInt(1024);
                out.write(new byte[8]);
                out.flush();
                Thread.sleep(200);
            } catch (Exception e) {
                serverError.set(e);
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();

        try (TcpTunnelCarrier client = TcpTunnelCarrier.connect("127.0.0.1", server.getLocalPort())) {
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            assertThrows(IOException.class, () -> client.receive(new byte[16]));
        } finally {
            server.close();
            acceptor.join(2000);
        }

        // EOF → -1
        ServerSocket server2 = new ServerSocket(0);
        Thread closer = new Thread(() -> {
            try (Socket socket = server2.accept()) {
                socket.close();
            } catch (Exception ignored) {
                // teardown
            }
        });
        closer.setDaemon(true);
        closer.start();
        try (TcpTunnelCarrier client = TcpTunnelCarrier.connect("127.0.0.1", server2.getLocalPort())) {
            assertEquals(-1, client.receive(new byte[64]));
        } finally {
            server2.close();
            closer.join(2000);
        }
    }
}
