package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CookieCheckerTest {

    @Test
    void cookieReplyRoundTripAndMac2() {
        SecureRandom random = new SecureRandom();
        Key local = X25519.generate(random).publicKey();
        CookieChecker checker = new CookieChecker(local, random);
        byte[] src = new byte[] {10, 0, 0, 1};
        byte[] mac1 = new byte[16];
        Arrays.fill(mac1, (byte) 3);

        byte[] reply = checker.cookieReply(0x99, mac1, src, 1_000L);
        assertEquals(MessageSizes.HANDSHAKE_COOKIE, reply.length);
        assertEquals(MessageType.HANDSHAKE_COOKIE, MessageType.fromWire(reply[0] & 0xff));

        byte[] cookie = CookieChecker.openCookie(local, reply, mac1);
        assertEquals(16, cookie.length);

        byte[] msg = new byte[MessageSizes.HANDSHAKE_INITIATION];
        msg[0] = 1;
        CookieChecker.writeMac2(msg, cookie);
        assertTrue(CookieChecker.verifyMac2(msg, cookie));
        assertFalse(CookieChecker.verifyMac2(msg, new byte[16]));
        assertFalse(CookieChecker.verifyMac2(msg, null));
        assertArrayEquals(cookie, checker.cookieFor(src, 1_000L));
    }

    @Test
    void openCookieRejectsBadInputAndMac2NullClears() {
        SecureRandom random = new SecureRandom();
        Key local = X25519.generate(random).publicKey();
        byte[] mac1 = new byte[16];
        assertThrows(IllegalArgumentException.class, () -> CookieChecker.openCookie(local, new byte[8], mac1));

        byte[] msg = new byte[MessageSizes.HANDSHAKE_INITIATION];
        msg[0] = 1;
        CookieChecker.writeMac2(msg, null);
        byte[] mac2 = Arrays.copyOfRange(msg, msg.length - 16, msg.length);
        assertArrayEquals(new byte[16], mac2);

        CookieChecker checker = new CookieChecker(local, random);
        byte[] a = checker.cookieFor(new byte[] {1, 2, 3, 4}, 0L);
        checker.rotate(1L);
        byte[] b = checker.cookieFor(new byte[] {1, 2, 3, 4}, 1L);
        assertFalse(Arrays.equals(a, b));

        byte[] before = checker.cookieFor(new byte[] {9, 9, 9, 9}, 10_000L);
        checker.maybeRotate(10_000L + CookieChecker.SECRET_MAX_AGE_MS);
        byte[] after = checker.cookieFor(new byte[] {9, 9, 9, 9}, 10_000L + CookieChecker.SECRET_MAX_AGE_MS);
        assertFalse(Arrays.equals(before, after));
    }
}
