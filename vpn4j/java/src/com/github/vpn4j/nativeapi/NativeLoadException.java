package com.github.vpn4j.nativeapi;

/**
 * Typed failure when the C++ JNI library cannot be loaded (fail-fast policy).
 */
public final class NativeLoadException extends RuntimeException {

    public NativeLoadException(String message) {
        super(message);
    }

    public NativeLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}
