package com.github.vpn4j.nativeapi;

/**
 * JNI surface for TUN. Opaque {@code long} handles only — C++ owns the device bytes/fd.
 */
public final class TunNative {

    private TunNative() {
    }

    /** @return opaque handle, or 0 on failure (exception preferred) */
    public static native long open(String interfaceName);

    public static native void close(long handle);

    /** @return bytes read into staging owned by native side; length returned */
    public static native int read(long handle, byte[] dst, int offset, int length);

    public static native int write(long handle, byte[] src, int offset, int length);

    public static native String version();
}
