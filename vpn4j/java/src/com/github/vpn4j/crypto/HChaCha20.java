package com.github.vpn4j.crypto;

/**
 * HChaCha20 (draft-irtf-cfrg-xchacha) — derives a 32-byte subkey from key + 16-byte nonce.
 */
public final class HChaCha20 {

    private static final int[] SIGMA = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    private HChaCha20() {
    }

    public static byte[] derive(byte[] key32, byte[] nonce16) {
        if (key32.length != 32 || nonce16.length != 16) {
            throw new IllegalArgumentException("HChaCha20 needs 32-byte key and 16-byte nonce");
        }
        int[] state = new int[16];
        state[0] = SIGMA[0];
        state[1] = SIGMA[1];
        state[2] = SIGMA[2];
        state[3] = SIGMA[3];
        for (int i = 0; i < 8; i++) {
            state[4 + i] = leInt(key32, i * 4);
        }
        for (int i = 0; i < 4; i++) {
            state[12 + i] = leInt(nonce16, i * 4);
        }
        int[] x = state.clone();
        for (int i = 0; i < 10; i++) {
            // Diagonal indices follow Bernstein/libsodium (RFC 8439 §2.1 typo).
            quarter(x, 0, 4, 8, 12);
            quarter(x, 1, 5, 9, 13);
            quarter(x, 2, 6, 10, 14);
            quarter(x, 3, 7, 11, 15);
            quarter(x, 0, 5, 10, 15);
            quarter(x, 1, 6, 11, 12);
            quarter(x, 2, 7, 8, 13);
            quarter(x, 3, 4, 9, 14);
        }
        // HChaCha20 output: x0..x3 || x12..x15 (no final add)
        byte[] out = new byte[32];
        putLeInt(out, 0, x[0]);
        putLeInt(out, 4, x[1]);
        putLeInt(out, 8, x[2]);
        putLeInt(out, 12, x[3]);
        putLeInt(out, 16, x[12]);
        putLeInt(out, 20, x[13]);
        putLeInt(out, 24, x[14]);
        putLeInt(out, 28, x[15]);
        return out;
    }

    private static void quarter(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
    }

    private static int leInt(byte[] b, int off) {
        return (b[off] & 0xff)
                | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16)
                | ((b[off + 3] & 0xff) << 24);
    }

    private static void putLeInt(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }
}
