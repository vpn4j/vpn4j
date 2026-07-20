package com.github.vpn4j.config;

import com.github.vpn4j.engine.DeviceEngine;
import com.github.vpn4j.engine.NanoClock;
import com.github.vpn4j.transport.PacketCarrier;
import com.github.vpn4j.tun.TunPort;

import java.security.SecureRandom;

/**
 * Helpers to materialize runtime engines from {@link WgConfig}.
 */
public final class WgConfigs {

    private WgConfigs() {
    }

    public static DeviceEngine deviceEngine(WgConfig config, PacketCarrier carrier, TunPort tun) {
        return deviceEngine(config, carrier, tun, new SecureRandom(), NanoClock.system());
    }

    public static DeviceEngine deviceEngine(
            WgConfig config,
            PacketCarrier carrier,
            TunPort tun,
            SecureRandom random,
            NanoClock clock) {
        DeviceEngine engine = new DeviceEngine(config.identity(), carrier, tun, random, clock);
        for (PeerConfig peer : config.peers()) {
            engine.addPeer(peer);
        }
        return engine;
    }
}
