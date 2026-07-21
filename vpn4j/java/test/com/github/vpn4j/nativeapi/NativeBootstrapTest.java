package com.github.vpn4j.nativeapi;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeBootstrapTest {

    @AfterEach
    void clearProperty() {
        System.clearProperty("vpn4j.native.library");
    }

    @Test
    void missingExplicitPathFailsFast() {
        System.setProperty("vpn4j.native.library", "/nonexistent/vpn4j/libvpn4j_native.so");
        NativeLoadException ex = assertThrows(NativeLoadException.class, NativeBootstrap::load);
        assertTrue(ex.getMessage().contains("not a file"));
        assertFalse(NativeBootstrap.isLoaded());
    }

    @Test
    void directoryPathFailsFast(@TempDir Path dir) {
        System.setProperty("vpn4j.native.library", dir.toString());
        assertThrows(NativeLoadException.class, NativeBootstrap::load);
        assertFalse(NativeBootstrap.isLoaded());
    }

    @Test
    void loadLibraryPathFailsWhenUnset() {
        System.clearProperty("vpn4j.native.library");
        // Assumes VPN4J_NATIVE_LIBRARY is unset in the test environment.
        if (System.getenv("VPN4J_NATIVE_LIBRARY") != null
                && !System.getenv("VPN4J_NATIVE_LIBRARY").isEmpty()) {
            return; // skip — cannot clear process env portably
        }
        NativeLoadException ex = assertThrows(NativeLoadException.class, NativeBootstrap::load);
        assertTrue(ex.getMessage().contains("Failed to load"));
        assertFalse(NativeBootstrap.isLoaded());
    }
}
