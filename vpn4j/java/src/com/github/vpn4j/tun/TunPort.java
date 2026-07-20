package com.github.vpn4j.tun;

import java.io.Closeable;

/**
 * L3 packet face (native TUN or in-memory for tests).
 */
public interface TunPort extends Closeable {

    int read(byte[] dst, int offset, int length);

    void write(byte[] src, int offset, int length);
}
