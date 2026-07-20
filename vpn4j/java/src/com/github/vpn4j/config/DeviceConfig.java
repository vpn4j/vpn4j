package com.github.vpn4j.config;

/**
 * Device-level configuration. Immutable after build.
 */
public final class DeviceConfig {

    private final TransportMode transportMode;
    private final String interfaceName;
    private final int listenPort;
    private final String tcpTunnelHost;
    private final int tcpTunnelPort;

    private DeviceConfig(Builder builder) {
        this.transportMode = builder.transportMode;
        this.interfaceName = builder.interfaceName;
        this.listenPort = builder.listenPort;
        this.tcpTunnelHost = builder.tcpTunnelHost;
        this.tcpTunnelPort = builder.tcpTunnelPort;
    }

    public TransportMode transportMode() {
        return transportMode;
    }

    public String interfaceName() {
        return interfaceName;
    }

    public int listenPort() {
        return listenPort;
    }

    public String tcpTunnelHost() {
        return tcpTunnelHost;
    }

    public int tcpTunnelPort() {
        return tcpTunnelPort;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private TransportMode transportMode = TransportMode.TUN;
        private String interfaceName = "vpn4j0";
        private int listenPort = 51820;
        private String tcpTunnelHost = null;
        private int tcpTunnelPort = 0;

        public Builder transportMode(TransportMode transportMode) {
            this.transportMode = transportMode;
            return this;
        }

        public Builder interfaceName(String interfaceName) {
            this.interfaceName = interfaceName;
            return this;
        }

        public Builder listenPort(int listenPort) {
            this.listenPort = listenPort;
            return this;
        }

        public Builder tcpTunnel(String host, int port) {
            this.transportMode = TransportMode.TCP_TUNNEL;
            this.tcpTunnelHost = host;
            this.tcpTunnelPort = port;
            return this;
        }

        public DeviceConfig build() {
            if (transportMode == null) {
                throw new IllegalArgumentException("transportMode required");
            }
            if (interfaceName == null || interfaceName.isEmpty()) {
                throw new IllegalArgumentException("interfaceName required");
            }
            if (transportMode == TransportMode.TCP_TUNNEL) {
                if (tcpTunnelHost == null || tcpTunnelHost.isEmpty()) {
                    throw new IllegalArgumentException("tcpTunnelHost required for TCP_TUNNEL");
                }
                if (tcpTunnelPort <= 0 || tcpTunnelPort > 65535) {
                    throw new IllegalArgumentException("tcpTunnelPort out of range");
                }
            }
            if (listenPort < 0 || listenPort > 65535) {
                throw new IllegalArgumentException("listenPort out of range");
            }
            return new DeviceConfig(this);
        }
    }
}
