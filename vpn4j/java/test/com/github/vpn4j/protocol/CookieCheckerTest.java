package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
        assertArrayEquals(cookie, checker.cookieFor(src, 1_000L));
    }
}
