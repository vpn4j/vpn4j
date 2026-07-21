package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertThrows;

class CookieCheckerTypeTest {

    @Test
    void openCookieRejectsWrongType() {
        Key local = X25519.generate(new SecureRandom()).publicKey();
        byte[] msg = new byte[MessageSizes.HANDSHAKE_COOKIE];
        msg[0] = (byte) MessageType.DATA.wire();
        assertThrows(IllegalArgumentException.class, () -> CookieChecker.openCookie(local, msg, new byte[16]));
    }
}
