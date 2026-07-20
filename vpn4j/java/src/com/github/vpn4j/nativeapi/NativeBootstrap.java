package com.github.vpn4j.nativeapi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Fail-fast loader for {@code libvpn4j_native}. Mirrors tensor4j native load policy.
 */
public final class NativeBootstrap {

    private static final AtomicBoolean LOADED = new AtomicBoolean(false);

    private NativeBootstrap() {
    }

    public static boolean isLoaded() {
        return LOADED.get();
    }

    /**
     * Load once. Order: {@code VPN4J_NATIVE_LIBRARY} / {@code vpn4j.native.library}, then
     * {@code System.loadLibrary("vpn4j_native")}.
     */
    public static void load() {
        if (LOADED.get()) {
            return;
        }
        synchronized (NativeBootstrap.class) {
            if (LOADED.get()) {
                return;
            }
            String explicit = System.getProperty("vpn4j.native.library");
            if (explicit == null || explicit.isEmpty()) {
                explicit = System.getenv("VPN4J_NATIVE_LIBRARY");
            }
            try {
                if (explicit != null && !explicit.isEmpty()) {
                    Path path = Path.of(explicit);
                    if (!Files.isRegularFile(path)) {
                        throw new NativeLoadException("VPN4J_NATIVE_LIBRARY not a file: " + explicit);
                    }
                    System.load(path.toAbsolutePath().toString());
                } else {
                    System.loadLibrary("vpn4j_native");
                }
                LOADED.set(true);
            } catch (UnsatisfiedLinkError e) {
                throw new NativeLoadException(
                        "Failed to load libvpn4j_native (set VPN4J_NATIVE_LIBRARY or java.library.path)",
                        e);
            }
        }
    }
}
