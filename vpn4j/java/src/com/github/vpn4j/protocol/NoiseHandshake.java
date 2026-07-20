package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Blake2s;
import com.github.vpn4j.crypto.Bytes;
import com.github.vpn4j.crypto.ChaCha20Poly1305;
import com.github.vpn4j.crypto.Hkdf;
import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.Tai64n;
import com.github.vpn4j.crypto.X25519;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Noise_IKpsk2 handshake (WireGuard). Clean-room from the public protocol description.
 */
public final class NoiseHandshake {

    private final KeyPair staticIdentity;
    private final Key remoteStatic;
    private final byte[] presharedKey;
    private final SecureRandom random;

    private byte[] chainingKey;
    private byte[] hash;
    private KeyPair ephemeral;
    private Key remoteEphemeral;
    private int localIndex;
    private int remoteIndex;
    private boolean initiator;

    public NoiseHandshake(KeyPair staticIdentity, Key remoteStatic, byte[] presharedKey, SecureRandom random) {
        this.staticIdentity = Objects.requireNonNull(staticIdentity, "staticIdentity");
        this.remoteStatic = Objects.requireNonNull(remoteStatic, "remoteStatic");
        this.presharedKey = presharedKey == null ? new byte[32] : Arrays.copyOf(presharedKey, 32);
        this.random = random == null ? new SecureRandom() : random;
    }

    public byte[] createInitiation(int senderIndex) {
        return createInitiation(senderIndex, null);
    }

    public byte[] createInitiation(int senderIndex, byte[] cookie) {
        initiator = true;
        localIndex = senderIndex;
        initHash(remoteStatic.bytes());

        ephemeral = X25519.generate(random);
        byte[] msg = new byte[MessageSizes.HANDSHAKE_INITIATION];
        msg[0] = (byte) MessageType.HANDSHAKE_INITIATION.wire();
        Bytes.putIntLe(msg, 4, senderIndex);

        byte[] ephPub = ephemeral.publicKey().bytes();
        System.arraycopy(ephPub, 0, msg, 8, 32);
        mixHash(ephPub);
        chainingKey = Hkdf.kdf1(chainingKey, ephPub);

        byte[] dhEs = X25519.sharedSecret(ephemeral.privateKey(), remoteStatic);
        byte[][] kdfEs = Hkdf.kdf2(chainingKey, dhEs);
        chainingKey = kdfEs[0];
        byte[] key = kdfEs[1];
        byte[] encStatic = ChaCha20Poly1305.seal(key, 0L, staticIdentity.publicKey().bytes(), hash);
        System.arraycopy(encStatic, 0, msg, 40, encStatic.length);
        mixHash(encStatic);

        byte[] dhSs = X25519.sharedSecret(staticIdentity.privateKey(), remoteStatic);
        byte[][] kdfSs = Hkdf.kdf2(chainingKey, dhSs);
        chainingKey = kdfSs[0];
        key = kdfSs[1];
        byte[] encTs = ChaCha20Poly1305.seal(key, 0L, Tai64n.now(), hash);
        System.arraycopy(encTs, 0, msg, 88, encTs.length);
        mixHash(encTs);

        writeMacs(msg, remoteStatic.bytes(), cookie);
        return msg;
    }

    /**
     * Consume initiation as responder. {@code lookupStatic} maps decrypted initiator static public key
     * bytes to the expected remote (must match configured peer).
     */
    public void consumeInitiation(byte[] msg, Key expectedInitiatorStatic) {
        if (msg.length != MessageSizes.HANDSHAKE_INITIATION) {
            throw new IllegalArgumentException("bad initiation length");
        }
        if (MessageType.fromWire(msg[0] & 0xff) != MessageType.HANDSHAKE_INITIATION) {
            throw new IllegalArgumentException("not initiation");
        }
        if (!verifyMac1(msg, staticIdentity.publicKey().bytes())) {
            throw new IllegalArgumentException("mac1 invalid");
        }

        initiator = false;
        remoteIndex = Bytes.getIntLe(msg, 4);
        initHash(staticIdentity.publicKey().bytes());

        byte[] ephPub = Bytes.slice(msg, 8, 32);
        remoteEphemeral = new Key(ephPub);
        mixHash(ephPub);
        chainingKey = Hkdf.kdf1(chainingKey, ephPub);

        byte[] dhEs = X25519.sharedSecret(staticIdentity.privateKey(), remoteEphemeral);
        byte[][] kdfEs = Hkdf.kdf2(chainingKey, dhEs);
        chainingKey = kdfEs[0];
        byte[] key = kdfEs[1];
        byte[] encStatic = Bytes.slice(msg, 40, NoiseLengths.encryptedLen(32));
        byte[] theirStatic = ChaCha20Poly1305.open(key, 0L, encStatic, hash);
        mixHash(encStatic);
        if (!Bytes.constantTimeEquals(theirStatic, expectedInitiatorStatic.bytes())) {
            throw new IllegalArgumentException("unexpected initiator static key");
        }

        byte[] dhSs = X25519.sharedSecret(staticIdentity.privateKey(), expectedInitiatorStatic);
        byte[][] kdfSs = Hkdf.kdf2(chainingKey, dhSs);
        chainingKey = kdfSs[0];
        key = kdfSs[1];
        byte[] encTs = Bytes.slice(msg, 88, NoiseLengths.encryptedLen(12));
        ChaCha20Poly1305.open(key, 0L, encTs, hash);
        mixHash(encTs);
    }

    public byte[] createResponse(int senderIndex) {
        if (initiator) {
            throw new IllegalStateException("initiator cannot create response");
        }
        localIndex = senderIndex;
        ephemeral = X25519.generate(random);

        byte[] msg = new byte[MessageSizes.HANDSHAKE_RESPONSE];
        msg[0] = (byte) MessageType.HANDSHAKE_RESPONSE.wire();
        Bytes.putIntLe(msg, 4, senderIndex);
        Bytes.putIntLe(msg, 8, remoteIndex);

        byte[] ephPub = ephemeral.publicKey().bytes();
        System.arraycopy(ephPub, 0, msg, 12, 32);
        mixHash(ephPub);
        chainingKey = Hkdf.kdf1(chainingKey, ephPub);

        byte[] dhEe = X25519.sharedSecret(ephemeral.privateKey(), remoteEphemeral);
        chainingKey = Hkdf.kdf1(chainingKey, dhEe);

        byte[] dhSe = X25519.sharedSecret(ephemeral.privateKey(), remoteStatic);
        chainingKey = Hkdf.kdf1(chainingKey, dhSe);

        byte[][] kdfPsk = Hkdf.kdf3(chainingKey, presharedKey);
        chainingKey = kdfPsk[0];
        byte[] temp2 = kdfPsk[1];
        byte[] key = kdfPsk[2];
        mixHash(temp2);

        byte[] encEmpty = ChaCha20Poly1305.seal(key, 0L, new byte[0], hash);
        System.arraycopy(encEmpty, 0, msg, 44, encEmpty.length);
        mixHash(encEmpty);

        writeMacs(msg, remoteStatic.bytes(), null);
        return msg;
    }

    public TransportKeys consumeResponse(byte[] msg) {
        if (!initiator) {
            throw new IllegalStateException("responder cannot consume response");
        }
        if (msg.length != MessageSizes.HANDSHAKE_RESPONSE) {
            throw new IllegalArgumentException("bad response length");
        }
        if (MessageType.fromWire(msg[0] & 0xff) != MessageType.HANDSHAKE_RESPONSE) {
            throw new IllegalArgumentException("not response");
        }
        if (!verifyMac1(msg, staticIdentity.publicKey().bytes())) {
            throw new IllegalArgumentException("mac1 invalid");
        }
        int theirIndex = Bytes.getIntLe(msg, 4);
        int echoIndex = Bytes.getIntLe(msg, 8);
        if (echoIndex != localIndex) {
            throw new IllegalArgumentException("receiver index mismatch");
        }
        remoteIndex = theirIndex;

        byte[] ephPub = Bytes.slice(msg, 12, 32);
        remoteEphemeral = new Key(ephPub);
        mixHash(ephPub);
        chainingKey = Hkdf.kdf1(chainingKey, ephPub);

        byte[] dhEe = X25519.sharedSecret(ephemeral.privateKey(), remoteEphemeral);
        chainingKey = Hkdf.kdf1(chainingKey, dhEe);

        byte[] dhSe = X25519.sharedSecret(staticIdentity.privateKey(), remoteEphemeral);
        chainingKey = Hkdf.kdf1(chainingKey, dhSe);

        byte[][] kdfPsk = Hkdf.kdf3(chainingKey, presharedKey);
        chainingKey = kdfPsk[0];
        byte[] temp2 = kdfPsk[1];
        byte[] key = kdfPsk[2];
        mixHash(temp2);

        byte[] encEmpty = Bytes.slice(msg, 44, NoiseLengths.encryptedLen(0));
        ChaCha20Poly1305.open(key, 0L, encEmpty, hash);
        mixHash(encEmpty);

        return deriveTransportKeys(true);
    }

    public TransportKeys deriveTransportKeysAsResponder() {
        if (initiator) {
            throw new IllegalStateException("use consumeResponse on initiator");
        }
        return deriveTransportKeys(false);
    }

    private TransportKeys deriveTransportKeys(boolean asInitiator) {
        byte[][] keys = Hkdf.kdf2(chainingKey, new byte[0]);
        Key send;
        Key recv;
        if (asInitiator) {
            send = new Key(keys[0]);
            recv = new Key(keys[1]);
        } else {
            recv = new Key(keys[0]);
            send = new Key(keys[1]);
        }
        return new TransportKeys(send, recv, localIndex, remoteIndex);
    }

    private void initHash(byte[] mixPublic) {
        chainingKey = Blake2s.hash32(ProtocolConstants.CONSTRUCTION);
        hash = Blake2s.hash32(Bytes.concat(chainingKey, ProtocolConstants.IDENTIFIER));
        hash = Blake2s.hash32(Bytes.concat(hash, mixPublic));
    }

    private void mixHash(byte[] data) {
        hash = Blake2s.hash32(Bytes.concat(hash, data));
    }

    private void writeMacs(byte[] msg, byte[] peerStatic, byte[] cookie) {
        int mac1Off = msg.length - 32;
        byte[] macKey = Blake2s.hash32(Bytes.concat(ProtocolConstants.LABEL_MAC1, peerStatic));
        byte[] mac1 = Blake2s.mac(macKey, Bytes.slice(msg, 0, mac1Off), 16);
        System.arraycopy(mac1, 0, msg, mac1Off, 16);
        CookieChecker.writeMac2(msg, cookie);
    }

    private boolean verifyMac1(byte[] msg, byte[] localStatic) {
        int mac1Off = msg.length - 32;
        byte[] macKey = Blake2s.hash32(Bytes.concat(ProtocolConstants.LABEL_MAC1, localStatic));
        byte[] expected = Blake2s.mac(macKey, Bytes.slice(msg, 0, mac1Off), 16);
        return Bytes.constantTimeEquals(expected, Bytes.slice(msg, mac1Off, 16));
    }

    public static byte[] mac1Of(byte[] msg) {
        return Bytes.slice(msg, msg.length - 32, 16);
    }

    public static boolean checkMac1(byte[] msg, Key localStatic) {
        int mac1Off = msg.length - 32;
        byte[] macKey = Blake2s.hash32(Bytes.concat(ProtocolConstants.LABEL_MAC1, localStatic.bytes()));
        byte[] expected = Blake2s.mac(macKey, Bytes.slice(msg, 0, mac1Off), 16);
        return Bytes.constantTimeEquals(expected, Bytes.slice(msg, mac1Off, 16));
    }
}
