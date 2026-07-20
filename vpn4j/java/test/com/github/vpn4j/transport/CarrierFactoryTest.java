package com.github.vpn4j.transport;

import com.github.vpn4j.config.DeviceConfig;
import com.github.vpn4j.config.TransportMode;

import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CarrierFactoryTest {

    @Test
    void openTunModeBindsUdp() throws Exception {
        DeviceConfig cfg = DeviceConfig.builder().transportMode(TransportMode.TUN).listenPort(0).build();
        try (PacketCarrier carrier = CarrierFactory.open(cfg)) {
            assertTrue(carrier instanceof UdpCarrier);
        }
    }

    @Test
    void openTcpTunnelConnects() throws Exception {
        CountDownLatch accepted = new CountDownLatch(1);
        ServerSocket server = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            try (Socket ignored = server.accept()) {
                accepted.countDown();
                Thread.sleep(200);
            } catch (Exception ignored) {
                // teardown
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();

        DeviceConfig cfg = DeviceConfig.builder().tcpTunnel("127.0.0.1", server.getLocalPort()).build();
        try (PacketCarrier carrier = CarrierFactory.open(cfg)) {
            assertTrue(carrier instanceof TcpTunnelCarrier);
            assertTrue(accepted.await(5, TimeUnit.SECONDS));
        } finally {
            server.close();
            acceptor.join(2000);
        }
    }
}
