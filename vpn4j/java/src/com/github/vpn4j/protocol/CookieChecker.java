package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Blake2s;
import com.github.vpn4j.crypto.Bytes;
import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.XChaCha20Poly1305;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * WireGuard cookie secrets / mac2 / cookie-reply (DoS mitigation).
 */
public final class CookieChecker {

    public static final long SECRET_MAX_AGE_MS = 120_000L;

    private final Key localStatic;
    private final SecureRandom random;
    private byte[] secret = new byte[32];
    private long secretBornMs;

    public CookieChecker(Key localStatic, SecureRandom random) {
        this.localStatic = localStatic;
        this.random = random == null ? new SecureRandom() : random;
        rotate(0L);
    }

    public synchronized void rotate(long nowMs) {
        random.nextBytes(secret);
        secretBornMs = nowMs;
    }

    public synchronized void maybeRotate(long nowMs) {
        if (nowMs - secretBornMs >= SECRET_MAX_AGE_MS) {
            rotate(nowMs);
        }
    }

    public synchronized byte[] cookieFor(byte[] srcAddr, long nowMs) {
        maybeRotate(nowMs);
        return Blake2s.mac(secret, srcAddr, NoiseLengths.COOKIE);
    }

    public byte[] cookieReply(int receiverIndex, byte[] mac1, byte[] srcAddr, long nowMs) {
        byte[] cookie = cookieFor(srcAddr, nowMs);
        byte[] nonce = new byte[NoiseLengths.COOKIE_NONCE];
        random.nextBytes(nonce);
        byte[] key = Blake2s.hash32(Bytes.concat(ProtocolConstants.LABEL_COOKIE, localStatic.bytes()));
        byte[] enc = XChaCha20Poly1305.seal(key, nonce, cookie, mac1);

        byte[] msg = new byte[MessageSizes.HANDSHAKE_COOKIE];
        msg[0] = (byte) MessageType.HANDSHAKE_COOKIE.wire();
        Bytes.putIntLe(msg, 4, receiverIndex);
        System.arraycopy(nonce, 0, msg, 8, nonce.length);
        System.arraycopy(enc, 0, msg, 8 + nonce.length, enc.length);
        return msg;
    }

    public static byte[] openCookie(Key remoteStatic, byte[] cookieMsg, byte[] mac1) {
        if (cookieMsg.length != MessageSizes.HANDSHAKE_COOKIE) {
            throw new IllegalArgumentException("bad cookie reply length");
        }
        if (MessageType.fromWire(cookieMsg[0] & 0xff) != MessageType.HANDSHAKE_COOKIE) {
            throw new IllegalArgumentException("not cookie reply");
        }
        byte[] nonce = Bytes.slice(cookieMsg, 8, NoiseLengths.COOKIE_NONCE);
        byte[] enc = Bytes.slice(
                cookieMsg,
                8 + NoiseLengths.COOKIE_NONCE,
                NoiseLengths.encryptedLen(NoiseLengths.COOKIE));
        byte[] key = Blake2s.hash32(Bytes.concat(ProtocolConstants.LABEL_COOKIE, remoteStatic.bytes()));
        return XChaCha20Poly1305.open(key, nonce, enc, mac1);
    }

    public static boolean verifyMac2(byte[] msg, byte[] cookie) {
        if (cookie == null || cookie.length != NoiseLengths.COOKIE) {
            return false;
        }
        int mac2Off = msg.length - NoiseLengths.COOKIE;
        byte[] expected = Blake2s.mac(cookie, Bytes.slice(msg, 0, mac2Off), NoiseLengths.COOKIE);
        return Bytes.constantTimeEquals(expected, Bytes.slice(msg, mac2Off, NoiseLengths.COOKIE));
    }

    public static void writeMac2(byte[] msg, byte[] cookie) {
        if (cookie == null) {
            Arrays.fill(msg, msg.length - NoiseLengths.COOKIE, msg.length, (byte) 0);
            return;
        }
        int mac2Off = msg.length - NoiseLengths.COOKIE;
        byte[] mac2 = Blake2s.mac(cookie, Bytes.slice(msg, 0, mac2Off), NoiseLengths.COOKIE);
        System.arraycopy(mac2, 0, msg, mac2Off, NoiseLengths.COOKIE);
    }
}
