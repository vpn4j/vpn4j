package com.github.vpn4j.transport;

import com.github.vpn4j.config.DeviceConfig;
import com.github.vpn4j.config.TransportMode;

import java.io.IOException;

/**
 * Build a {@link PacketCarrier} from {@link DeviceConfig}.
 */
public final class CarrierFactory {

    private CarrierFactory() {
    }

    public static PacketCarrier open(DeviceConfig config) throws IOException {
        if (config.transportMode() == TransportMode.TCP_TUNNEL) {
            return TcpTunnelCarrier.connect(config.tcpTunnelHost(), config.tcpTunnelPort());
        }
        return UdpCarrier.bind(config.listenPort());
    }
}
