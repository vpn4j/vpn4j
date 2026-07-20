package com.github.vpn4j.device;

import com.github.vpn4j.tun.TunPort;

/**
 * Adapts {@link TunDevice} to {@link TunPort}.
 */
public final class NativeTunPort implements TunPort {

    private final TunDevice device;

    public NativeTunPort(TunDevice device) {
        this.device = device;
    }

    @Override
    public int read(byte[] dst, int offset, int length) {
        return device.read(dst, offset, length);
    }

    @Override
    public void write(byte[] src, int offset, int length) {
        device.write(src, offset, length);
    }

    @Override
    public void close() {
        device.close();
    }
}
