package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.Bytes;
import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.protocol.AllowedIpsTable;
import com.github.vpn4j.protocol.MessageType;
import com.github.vpn4j.transport.PacketCarrier;
import com.github.vpn4j.tun.TunPort;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Multi-peer engine demuxing one shared {@link PacketCarrier} and {@link TunPort}.
 */
public final class DeviceEngine implements AutoCloseable {

    private final KeyPair identity;
    private final PacketCarrier carrier;
    private final TunPort tun;
    private final SecureRandom random;
    private final NanoClock clock;
    private final Map<Key, PeerEngine> peers = new LinkedHashMap<>();
    private final AllowedIpsTable<PeerEngine> allowedIps = new AllowedIpsTable<>();
    private boolean closed;

    public DeviceEngine(KeyPair identity, PacketCarrier carrier, TunPort tun) {
        this(identity, carrier, tun, new SecureRandom(), NanoClock.system());
    }

    public DeviceEngine(
            KeyPair identity,
            PacketCarrier carrier,
            TunPort tun,
            SecureRandom random,
            NanoClock clock) {
        this.identity = Objects.requireNonNull(identity, "identity");
        this.carrier = Objects.requireNonNull(carrier, "carrier");
        this.tun = Objects.requireNonNull(tun, "tun");
        this.random = random == null ? new SecureRandom() : random;
        this.clock = clock == null ? NanoClock.system() : clock;
    }

    public synchronized PeerEngine addPeer(PeerConfig peer) {
        ensureOpen();
        Key key = peer.publicKey();
        if (peers.containsKey(key)) {
            throw new IllegalArgumentException("peer already added");
        }
        PeerEngine engine = new PeerEngine(identity, peer, carrier, tun, random, clock);
        peers.put(key, engine);
        for (String cidr : peer.allowedIps()) {
            allowedIps.insert(cidr, engine);
        }
        return engine;
    }

    public synchronized PeerEngine peer(Key publicKey) {
        return peers.get(publicKey);
    }

    public synchronized List<PeerEngine> peers() {
        return new ArrayList<>(peers.values());
    }

    public synchronized void initiate(Key peerPublicKey) throws IOException {
        PeerEngine engine = requirePeer(peerPublicKey);
        engine.initiate();
    }

    /**
     * Receive one wire packet (if any), demux to the owning peer, drain TUN via allowed-IPs,
     * then tick timers on all peers.
     */
    public synchronized boolean pumpOnce() throws IOException {
        ensureOpen();
        boolean work = false;
        byte[] wireBuf = new byte[65535];
        int n = carrier.receive(wireBuf);
        if (n > 0) {
            work |= demuxWire(wireBuf, n);
        }
        work |= pumpTunRouted();
        for (PeerEngine peer : peers.values()) {
            if (peer.tick()) {
                work = true;
            }
        }
        return work;
    }

    boolean demuxWire(byte[] packet, int length) throws IOException {
        MessageType type = MessageType.fromWire(packet[0] & 0xff);
        switch (type) {
            case HANDSHAKE_RESPONSE:
                return demuxResponse(packet, length);
            case DATA:
                return demuxData(packet, length);
            case HANDSHAKE_INITIATION:
                return demuxInitiation(packet, length);
            case HANDSHAKE_COOKIE:
                return demuxCookie(packet, length);
            default:
                return false;
        }
    }

    private boolean demuxCookie(byte[] packet, int length) throws IOException {
        if (length < 8) {
            return false;
        }
        int receiverIndex = Bytes.getIntLe(packet, 4);
        for (PeerEngine peer : peers.values()) {
            if (peer.localIndex() == receiverIndex) {
                peer.tryHandleWire(packet, length);
                return peer.hasCookie();
            }
        }
        return false;
    }

    public synchronized void setUnderLoad(boolean underLoad) {
        for (PeerEngine peer : peers.values()) {
            peer.setUnderLoad(underLoad);
        }
    }

    private boolean demuxResponse(byte[] packet, int length) throws IOException {
        if (length < 12) {
            return false;
        }
        int echoIndex = Bytes.getIntLe(packet, 8);
        for (PeerEngine peer : peers.values()) {
            if (peer.localIndex() == echoIndex && peer.hasPendingHandshake()) {
                boolean before = peer.established();
                peer.tryHandleWire(packet, length);
                return !before && peer.established();
            }
        }
        return false;
    }

    private boolean demuxData(byte[] packet, int length) throws IOException {
        if (length < 8) {
            return false;
        }
        int receiverIndex = Bytes.getIntLe(packet, 4);
        for (PeerEngine peer : peers.values()) {
            if (peer.ownsReceiverIndex(receiverIndex)) {
                return peer.tryHandleWire(packet, length);
            }
        }
        return false;
    }

    private boolean demuxInitiation(byte[] packet, int length) throws IOException {
        for (PeerEngine peer : peers.values()) {
            boolean before = peer.established();
            peer.tryHandleWire(packet, length);
            if (!before && peer.established()) {
                return true;
            }
        }
        return false;
    }

    private boolean pumpTunRouted() throws IOException {
        byte[] tunBuf = new byte[65535];
        int t = tun.read(tunBuf, 0, tunBuf.length);
        if (t <= 0) {
            return false;
        }
        PeerEngine route = routeByAllowedIps(tunBuf, t);
        if (route == null || !route.established()) {
            return false;
        }
        route.handleTunOutbound(tunBuf, t);
        return true;
    }

    /** LPM only (ignores session state) — for tests / diagnostics. */
    PeerEngine lookupAllowedIp(byte[] packet, int length) {
        return allowedIps.lookupDestination(packet, length);
    }

    /**
     * Longest-prefix match on destination against peer allowed IPs. No match or down → null.
     */
    PeerEngine routeByAllowedIps(byte[] packet, int length) {
        PeerEngine peer = lookupAllowedIp(packet, length);
        if (peer == null || !peer.established()) {
            return null;
        }
        return peer;
    }

    private PeerEngine requirePeer(Key publicKey) {
        PeerEngine engine = peers.get(publicKey);
        if (engine == null) {
            throw new IllegalArgumentException("unknown peer");
        }
        return engine;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("DeviceEngine closed");
        }
    }

    @Override
    public synchronized void close() {
        closed = true;
        for (PeerEngine peer : peers.values()) {
            peer.close();
        }
        peers.clear();
    }
}
