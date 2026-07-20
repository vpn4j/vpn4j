package com.github.vpn4j.crypto;

/**
 * BLAKE2s (RFC 7693) — hash and keyed MAC. Clean-room from the RFC.
 */
public final class Blake2s {

    private static final int[] IV = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    private static final byte[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
    };

    private final int outLen;
    private final int[] h = new int[8];
    private final byte[] buf = new byte[64];
    private int bufLen;
    private long t0;
    private long t1;
    private boolean lastNode;

    public Blake2s(int outLen) {
        this(outLen, null);
    }

    public Blake2s(int outLen, byte[] key) {
        if (outLen < 1 || outLen > 32) {
            throw new IllegalArgumentException("outLen 1..32");
        }
        this.outLen = outLen;
        System.arraycopy(IV, 0, h, 0, 8);
        int keyLen = key == null ? 0 : key.length;
        if (keyLen > 32) {
            throw new IllegalArgumentException("key length 0..32");
        }
        h[0] ^= 0x01010000 ^ (keyLen << 8) ^ outLen;
        if (keyLen > 0) {
            byte[] block = new byte[64];
            System.arraycopy(key, 0, block, 0, keyLen);
            update(block, 0, 64);
        }
    }

    public static byte[] hash(byte[] input, int outLen) {
        Blake2s b = new Blake2s(outLen);
        b.update(input, 0, input.length);
        return b.digest();
    }

    public static byte[] hash32(byte[] input) {
        return hash(input, 32);
    }

    /** Keyed BLAKE2s truncated to {@code outLen} (WireGuard MAC uses 16). */
    public static byte[] mac(byte[] key, byte[] input, int outLen) {
        Blake2s b = new Blake2s(outLen, key);
        b.update(input, 0, input.length);
        return b.digest();
    }

    public void update(byte[] in, int offset, int length) {
        int i = offset;
        int remaining = length;
        while (remaining > 0) {
            int space = 64 - bufLen;
            if (remaining <= space) {
                System.arraycopy(in, i, buf, bufLen, remaining);
                bufLen += remaining;
                return;
            }
            System.arraycopy(in, i, buf, bufLen, space);
            t0 += 64;
            if (t0 < 64) {
                t1++;
            }
            compress(buf, false);
            bufLen = 0;
            i += space;
            remaining -= space;
        }
    }

    public byte[] digest() {
        t0 += bufLen;
        if (t0 < bufLen) {
            t1++;
        }
        while (bufLen < 64) {
            buf[bufLen++] = 0;
        }
        compress(buf, true);
        byte[] out = new byte[outLen];
        for (int i = 0; i < outLen; i++) {
            out[i] = (byte) (h[i >>> 2] >>> (8 * (i & 3)));
        }
        return out;
    }

    private void compress(byte[] block, boolean last) {
        int[] m = new int[16];
        for (int i = 0; i < 16; i++) {
            int j = i * 4;
            m[i] = (block[j] & 0xff)
                    | ((block[j + 1] & 0xff) << 8)
                    | ((block[j + 2] & 0xff) << 16)
                    | ((block[j + 3] & 0xff) << 24);
        }
        int[] v = new int[16];
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= (int) t0;
        v[13] ^= (int) (t0 >>> 32);
        v[14] ^= (int) t1;
        v[15] ^= (int) (t1 >>> 32);
        if (last) {
            v[14] = ~v[14];
        }
        if (lastNode) {
            v[15] = ~v[15];
        }
        for (int round = 0; round < 10; round++) {
            byte[] s = SIGMA[round];
            g(v, m, 0, 4, 8, 12, s[0], s[1]);
            g(v, m, 1, 5, 9, 13, s[2], s[3]);
            g(v, m, 2, 6, 10, 14, s[4], s[5]);
            g(v, m, 3, 7, 11, 15, s[6], s[7]);
            g(v, m, 0, 5, 10, 15, s[8], s[9]);
            g(v, m, 1, 6, 11, 12, s[10], s[11]);
            g(v, m, 2, 7, 8, 13, s[12], s[13]);
            g(v, m, 3, 4, 9, 14, s[14], s[15]);
        }
        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static void g(int[] v, int[] m, int a, int b, int c, int d, int x, int y) {
        v[a] = v[a] + v[b] + m[x];
        v[d] = Integer.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Integer.rotateRight(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + m[y];
        v[d] = Integer.rotateRight(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = Integer.rotateRight(v[b] ^ v[c], 7);
    }
}
