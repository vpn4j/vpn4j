package com.github.vpn4j.device;

import com.github.vpn4j.nativeapi.NativeBootstrap;
import com.github.vpn4j.nativeapi.TunNative;

import java.lang.ref.Cleaner;

/**
 * Java face of a native TUN. Primary free path is {@link #close()}; Cleaner is a safety net only.
 */
public final class TunDevice implements AutoCloseable {

    private static final Cleaner CLEANER = Cleaner.create();

    private final long handle;
    private final Cleaner.Cleanable cleanable;
    private boolean closed;

    private TunDevice(long handle) {
        this.handle = handle;
        this.cleanable = CLEANER.register(this, new NativeClose(handle));
        this.closed = false;
    }

    public static TunDevice open(String interfaceName) {
        NativeBootstrap.load();
        long handle = TunNative.open(interfaceName);
        if (handle == 0L) {
            throw new IllegalStateException("TunNative.open returned null handle");
        }
        return new TunDevice(handle);
    }

    public long handle() {
        return handle;
    }

    public int read(byte[] dst, int offset, int length) {
        ensureOpen();
        return TunNative.read(handle, dst, offset, length);
    }

    public int write(byte[] src, int offset, int length) {
        ensureOpen();
        return TunNative.write(handle, src, offset, length);
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        cleanable.clean();
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("TunDevice closed");
        }
    }

    private static final class NativeClose implements Runnable {
        private final long handle;

        NativeClose(long handle) {
            this.handle = handle;
        }

        @Override
        public void run() {
            if (handle != 0L) {
                TunNative.close(handle);
            }
        }
    }
}
