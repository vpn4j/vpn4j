package com.github.vpn4j.nativeapi;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class NativeLoadExceptionTest {

    @Test
    void carriesMessageAndCause() {
        Throwable cause = new UnsatisfiedLinkError("boom");
        NativeLoadException ex = new NativeLoadException("failed", cause);
        assertEquals("failed", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertEquals("solo", new NativeLoadException("solo").getMessage());
    }
}
