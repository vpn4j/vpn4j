package com.github.vpn4j.crypto;

import java.util.Arrays;

public final class Bytes {

    private Bytes() {
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    public static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] out = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        System.arraycopy(c, 0, out, a.length + b.length, c.length);
        return out;
    }

    public static byte[] slice(byte[] src, int offset, int length) {
        return Arrays.copyOfRange(src, offset, offset + length);
    }

    public static void putIntLe(byte[] dst, int offset, int value) {
        dst[offset] = (byte) value;
        dst[offset + 1] = (byte) (value >>> 8);
        dst[offset + 2] = (byte) (value >>> 16);
        dst[offset + 3] = (byte) (value >>> 24);
    }

    public static int getIntLe(byte[] src, int offset) {
        return (src[offset] & 0xff)
                | ((src[offset + 1] & 0xff) << 8)
                | ((src[offset + 2] & 0xff) << 16)
                | ((src[offset + 3] & 0xff) << 24);
    }

    public static void putLongLe(byte[] dst, int offset, long value) {
        for (int i = 0; i < 8; i++) {
            dst[offset + i] = (byte) (value >>> (8 * i));
        }
    }

    public static void putLongBe(byte[] dst, int offset, long value) {
        for (int i = 7; i >= 0; i--) {
            dst[offset + (7 - i)] = (byte) (value >>> (8 * i));
        }
    }

    public static void putIntBe(byte[] dst, int offset, int value) {
        dst[offset] = (byte) (value >>> 24);
        dst[offset + 1] = (byte) (value >>> 16);
        dst[offset + 2] = (byte) (value >>> 8);
        dst[offset + 3] = (byte) value;
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    public static void zero(byte[] a) {
        Arrays.fill(a, (byte) 0);
    }
}
