package com.github.vpn4j;

import com.github.vpn4j.nativeapi.NativeBootstrap;
import com.github.vpn4j.nativeapi.TunNative;

/**
 * Library entry / version surface.
 */
public final class Vpn4j {

    public static final String VERSION = "1.0.0-SNAPSHOT";

    private Vpn4j() {
    }

    public static String version() {
        return VERSION;
    }

    /** Native library version string after fail-fast load. */
    public static String nativeVersion() {
        NativeBootstrap.load();
        return TunNative.version();
    }
}
