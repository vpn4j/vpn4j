package com.github.vpn4j.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DeviceConfigTest {

    @Test
    void tunDefaults() {
        DeviceConfig cfg = DeviceConfig.builder().build();
        assertEquals(TransportMode.TUN, cfg.transportMode());
        assertEquals("vpn4j0", cfg.interfaceName());
        assertEquals(51820, cfg.listenPort());
    }

    @Test
    void tcpTunnelRequiresHostPort() {
        DeviceConfig.Builder builder = DeviceConfig.builder()
                .transportMode(TransportMode.TCP_TUNNEL);
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void tcpTunnelOk() {
        DeviceConfig cfg = DeviceConfig.builder()
                .tcpTunnel("127.0.0.1", 443)
                .build();
        assertEquals(TransportMode.TCP_TUNNEL, cfg.transportMode());
        assertEquals("127.0.0.1", cfg.tcpTunnelHost());
        assertEquals(443, cfg.tcpTunnelPort());
    }

    @Test
    void rejectsBadListenPortAndEmptyName() {
        assertThrows(
                IllegalArgumentException.class,
                () -> DeviceConfig.builder().listenPort(70000).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> DeviceConfig.builder().interfaceName("").build());
    }

    @Test
    void rejectsNullTransportModeAndBadTcpPort() {
        assertThrows(
                IllegalArgumentException.class,
                () -> DeviceConfig.builder().transportMode(null).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> DeviceConfig.builder().tcpTunnel("127.0.0.1", 0).build());
    }
}
