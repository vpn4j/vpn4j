package com.github.vpn4j.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class X25519ErrorTest {

    @Test
    void generalSecurityRuntimeCarriesCause() {
        Throwable cause = new Exception("root");
        X25519.GeneralSecurityRuntime ex = new X25519.GeneralSecurityRuntime("wrap", cause);
        assertEquals("wrap", ex.getMessage());
        assertSame(cause, ex.getCause());
    }

    @Test
    void clampRejectsBadLength() {
        assertThrows(IllegalArgumentException.class, () -> KeyPair.clampCurve25519(new byte[16]));
    }
}
