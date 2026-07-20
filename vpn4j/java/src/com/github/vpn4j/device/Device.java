package com.github.vpn4j.device;

import com.github.vpn4j.config.DeviceConfig;
import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.config.TransportMode;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.engine.DeviceEngine;
import com.github.vpn4j.engine.NanoClock;
import com.github.vpn4j.engine.PeerEngine;
import com.github.vpn4j.transport.PacketCarrier;
import com.github.vpn4j.tun.TunPort;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Logical WireGuard-compatible device. TUN open is optional until {@link #attachTun()}.
 */
public final class Device implements AutoCloseable {

    private final DeviceConfig config;
    private final KeyPair identity;
    private final SecureRandom random;
    private final List<PeerConfig> peers = new ArrayList<>();
    private TunDevice tun;
    private boolean closed;

    public Device(DeviceConfig config, KeyPair identity) {
        this(config, identity, new SecureRandom());
    }

    public Device(DeviceConfig config, KeyPair identity, SecureRandom random) {
        this.config = Objects.requireNonNull(config, "config");
        this.identity = Objects.requireNonNull(identity, "identity");
        this.random = random == null ? new SecureRandom() : random;
    }

    public DeviceConfig config() {
        return config;
    }

    public KeyPair identity() {
        return identity;
    }

    public TransportMode transportMode() {
        return config.transportMode();
    }

    public synchronized void addPeer(PeerConfig peer) {
        ensureOpen();
        peers.add(Objects.requireNonNull(peer, "peer"));
    }

    public synchronized List<PeerConfig> peers() {
        return Collections.unmodifiableList(new ArrayList<>(peers));
    }

    /**
     * Open the native TUN for {@link TransportMode#TUN} (and as the L3 face for TCP tunnel mode).
     */
    public synchronized TunDevice attachTun() {
        ensureOpen();
        if (tun != null) {
            return tun;
        }
        tun = TunDevice.open(config.interfaceName());
        return tun;
    }

    public synchronized TunDevice tun() {
        return tun;
    }

    /**
     * Create a peer engine bound to this device identity. Caller owns {@code carrier} and {@code tunPort}.
     */
    public PeerEngine engineFor(PeerConfig peer, PacketCarrier carrier, TunPort tunPort) {
        ensureOpen();
        return new PeerEngine(identity, peer, carrier, tunPort, random);
    }

    /**
     * Multi-peer engine sharing one carrier + TUN. Caller owns {@code carrier} and {@code tunPort}.
     */
    public DeviceEngine deviceEngine(PacketCarrier carrier, TunPort tunPort) {
        ensureOpen();
        return new DeviceEngine(identity, carrier, tunPort, random, NanoClock.system());
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (tun != null) {
            tun.close();
            tun = null;
        }
        peers.clear();
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("Device closed");
        }
    }
}
