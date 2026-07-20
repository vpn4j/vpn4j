package com.github.vpn4j.engine;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.crypto.Bytes;
import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.protocol.CookieChecker;
import com.github.vpn4j.protocol.MessageSizes;
import com.github.vpn4j.protocol.MessageType;
import com.github.vpn4j.protocol.NoiseHandshake;
import com.github.vpn4j.protocol.TransportSession;
import com.github.vpn4j.transport.PacketCarrier;
import com.github.vpn4j.tun.TunPort;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One-peer engine: Noise handshake over a {@link PacketCarrier}, then TUN ↔ data packets.
 */
public final class PeerEngine implements AutoCloseable {

    private static final AtomicInteger INDEXES = new AtomicInteger(0x1000);

    private final KeyPair identity;
    private final PeerConfig peer;
    private final PacketCarrier carrier;
    private final TunPort tun;
    private final SecureRandom random;
    private final int localIndex;
    private final SessionTimers timers;
    private final NanoClock clock;
    private final CookieChecker cookies;

    private final Object lock = new Object();
    private NoiseHandshake handshake;
    private TransportSession session;
    private SocketAddress remoteEndpoint;
    private boolean closed;
    private boolean roleInitiator;
    private boolean underLoad;
    private byte[] lastCookie;
    private byte[] lastInitiationMac1;

    public PeerEngine(KeyPair identity, PeerConfig peer, PacketCarrier carrier, TunPort tun, SecureRandom random) {
        this(identity, peer, carrier, tun, random, NanoClock.system());
    }

    public PeerEngine(
            KeyPair identity,
            PeerConfig peer,
            PacketCarrier carrier,
            TunPort tun,
            SecureRandom random,
            NanoClock clock) {
        this.identity = Objects.requireNonNull(identity, "identity");
        this.peer = Objects.requireNonNull(peer, "peer");
        this.carrier = Objects.requireNonNull(carrier, "carrier");
        this.tun = Objects.requireNonNull(tun, "tun");
        this.random = random == null ? new SecureRandom() : random;
        this.clock = clock == null ? NanoClock.system() : clock;
        this.localIndex = INDEXES.getAndIncrement();
        this.remoteEndpoint = peer.endpoint();
        this.timers = new SessionTimers(this.clock, peer.persistentKeepaliveSeconds());
        this.cookies = new CookieChecker(identity.publicKey(), this.random);
    }

    public void setUnderLoad(boolean underLoad) {
        this.underLoad = underLoad;
    }

    public boolean underLoad() {
        return underLoad;
    }

    public int localIndex() {
        return localIndex;
    }

    public PeerConfig peer() {
        return peer;
    }

    public Key peerPublicKey() {
        return peer.publicKey();
    }

    public boolean established() {
        synchronized (lock) {
            return session != null;
        }
    }

    public TransportSession session() {
        synchronized (lock) {
            return session;
        }
    }

    public SessionTimers timers() {
        return timers;
    }

    /** Send handshake initiation (initiator role). */
    public void initiate() throws IOException {
        ensureOpen();
        byte[] psk = pskBytes();
        byte[] msg;
        synchronized (lock) {
            roleInitiator = true;
            handshake = new NoiseHandshake(identity, peer.publicKey(), psk, random);
            msg = handshake.createInitiation(localIndex, lastCookie);
            lastInitiationMac1 = NoiseHandshake.mac1Of(msg);
            timers.onInitiationAttempt();
        }
        carrier.send(msg, requireEndpoint());
    }

    /**
     * Handle one inbound wire packet (handshake or data).
     *
     * @return true if a data packet was decrypted onto the TUN
     */
    public boolean handleWire(byte[] packet, int length) throws IOException {
        ensureOpen();
        if (packet == null || length <= 0) {
            return false;
        }
        byte[] msg = new byte[length];
        System.arraycopy(packet, 0, msg, 0, length);
        return handleWireMessage(msg);
    }

    /**
     * Like {@link #handleWire} but returns false on crypto/auth mismatch instead of throwing
     * (for multi-peer demux).
     */
    public boolean tryHandleWire(byte[] packet, int length) throws IOException {
        try {
            return handleWire(packet, length);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return false;
        }
    }

    /** Encrypt one TUN plaintext packet and send on the carrier. */
    public void handleTunOutbound(byte[] plaintext, int length) throws IOException {
        ensureOpen();
        TransportSession active;
        synchronized (lock) {
            if (session != null && timers.isRejectedByAge()) {
                session = null;
            }
            active = session;
        }
        if (active == null) {
            throw new IllegalStateException("session not established");
        }
        byte[] plain = new byte[length];
        System.arraycopy(plaintext, 0, plain, 0, length);
        byte[] wire = active.seal(plain);
        timers.onSent();
        carrier.send(wire, requireEndpoint());
    }

    /**
     * Apply keepalive / rekey actions for {@code now}.
     *
     * @return true if a packet was sent
     */
    public boolean tick() throws IOException {
        ensureOpen();
        synchronized (lock) {
            if (session != null && timers.isRejectedByAge()) {
                session = null;
                handshake = null;
            }
        }
        if (!established()) {
            return false;
        }
        if (timers.wantsRekey()) {
            initiate();
            return true;
        }
        if (timers.wantsKeepalive()) {
            sendKeepalive();
            return true;
        }
        return false;
    }

    public void sendKeepalive() throws IOException {
        handleTunOutbound(new byte[0], 0);
    }

    /**
     * Single pump step: receive wire → TUN, drain one TUN packet → wire, then timer tick.
     */
    public boolean pumpOnce() throws IOException {
        ensureOpen();
        boolean work = false;
        byte[] wireBuf = new byte[65535];
        int n = carrier.receive(wireBuf);
        if (n > 0) {
            handleWire(wireBuf, n);
            work = true;
        }
        work |= pumpTunOutboundOnce();
        work |= tick();
        return work;
    }

    /** Drain one TUN packet if session is up (shared-carrier friendly). */
    public boolean pumpTunOutboundOnce() throws IOException {
        if (!established()) {
            return false;
        }
        byte[] tunBuf = new byte[65535];
        int t = tun.read(tunBuf, 0, tunBuf.length);
        if (t > 0) {
            handleTunOutbound(tunBuf, t);
            return true;
        }
        return false;
    }

    public boolean ownsReceiverIndex(int receiverIndex) {
        synchronized (lock) {
            return session != null && session.keys().localIndex() == receiverIndex;
        }
    }

    public boolean hasPendingHandshake() {
        synchronized (lock) {
            return handshake != null && session == null;
        }
    }

    private boolean handleWireMessage(byte[] msg) throws IOException {
        MessageType type = MessageType.fromWire(msg[0] & 0xff);
        SocketAddress from = carrier.lastRemote();
        if (from != null) {
            remoteEndpoint = from;
        }

        switch (type) {
            case HANDSHAKE_INITIATION:
                handleInitiation(msg);
                return false;
            case HANDSHAKE_RESPONSE:
                handleResponse(msg);
                return false;
            case HANDSHAKE_COOKIE:
                handleCookie(msg);
                return false;
            case DATA:
                return handleData(msg);
            default:
                return false;
        }
    }

    private void handleInitiation(byte[] msg) throws IOException {
        if (msg.length != MessageSizes.HANDSHAKE_INITIATION) {
            throw new IllegalArgumentException("bad initiation length");
        }
        if (!NoiseHandshake.checkMac1(msg, identity.publicKey())) {
            throw new IllegalArgumentException("mac1 invalid");
        }
        SocketAddress from = remoteEndpoint != null ? remoteEndpoint : requireEndpoint();
        byte[] src = addressBytes(from);
        if (underLoad) {
            byte[] expectedCookie = cookies.cookieFor(src, clock.millis());
            if (!CookieChecker.verifyMac2(msg, expectedCookie)) {
                int senderIndex = Bytes.getIntLe(msg, 4);
                byte[] reply = cookies.cookieReply(
                        senderIndex, NoiseHandshake.mac1Of(msg), src, clock.millis());
                carrier.send(reply, from);
                return;
            }
        }
        byte[] psk = pskBytes();
        byte[] response;
        synchronized (lock) {
            NoiseHandshake hs = new NoiseHandshake(identity, peer.publicKey(), psk, random);
            hs.consumeInitiation(msg, peer.publicKey());
            response = hs.createResponse(localIndex);
            session = new TransportSession(hs.deriveTransportKeysAsResponder());
            handshake = null;
            roleInitiator = false;
            timers.onSessionEstablished(false);
        }
        carrier.send(response, from);
        timers.onSent();
    }

    private void handleCookie(byte[] msg) {
        if (msg.length != MessageSizes.HANDSHAKE_COOKIE) {
            throw new IllegalArgumentException("bad cookie length");
        }
        int receiverIndex = Bytes.getIntLe(msg, 4);
        if (receiverIndex != localIndex) {
            throw new IllegalArgumentException("cookie receiver mismatch");
        }
        synchronized (lock) {
            if (lastInitiationMac1 == null) {
                throw new IllegalStateException("no initiation mac1 for cookie");
            }
            lastCookie = CookieChecker.openCookie(peer.publicKey(), msg, lastInitiationMac1);
        }
    }

    public boolean hasCookie() {
        synchronized (lock) {
            return lastCookie != null;
        }
    }

    private static byte[] addressBytes(SocketAddress address) {
        if (address instanceof InetSocketAddress) {
            InetSocketAddress inet = (InetSocketAddress) address;
            if (inet.getAddress() != null) {
                return inet.getAddress().getAddress();
            }
        }
        return new byte[] {0, 0, 0, 0};
    }

    private void handleResponse(byte[] msg) {
        if (msg.length != MessageSizes.HANDSHAKE_RESPONSE) {
            throw new IllegalArgumentException("bad response length");
        }
        int echoIndex = Bytes.getIntLe(msg, 8);
        if (echoIndex != localIndex) {
            throw new IllegalArgumentException("receiver index mismatch");
        }
        synchronized (lock) {
            if (handshake == null) {
                throw new IllegalStateException("no pending handshake");
            }
            session = new TransportSession(handshake.consumeResponse(msg));
            handshake = null;
            timers.onSessionEstablished(true);
        }
        timers.onReceived();
    }

    private boolean handleData(byte[] msg) {
        TransportSession active;
        synchronized (lock) {
            if (session != null && timers.isRejectedByAge()) {
                session = null;
                return false;
            }
            active = session;
        }
        if (active == null) {
            return false;
        }
        byte[] plain = active.open(msg);
        if (plain == null) {
            return false;
        }
        timers.onReceived();
        if (plain.length > 0) {
            tun.write(plain, 0, plain.length);
        }
        return true;
    }

    private byte[] pskBytes() {
        return peer.presharedKey() == null ? null : peer.presharedKey().bytes();
    }

    private SocketAddress requireEndpoint() {
        SocketAddress ep = remoteEndpoint;
        if (ep == null) {
            throw new IllegalStateException("peer endpoint unknown");
        }
        return ep;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("PeerEngine closed");
        }
    }

    /** Clears session state. Does not close carrier/TUN (caller owns those). */
    @Override
    public void close() {
        closed = true;
        synchronized (lock) {
            handshake = null;
            session = null;
        }
    }
}
