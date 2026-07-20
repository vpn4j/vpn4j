package com.github.vpn4j.protocol;

/**
 * Sliding replay window for transport counters (WireGuard-style bitmap).
 *
 * <p>Bit {@code i} means counter {@code latest - i} has been seen. Bit 0 is always the latest.
 */
public final class ReplayWindow {

    public static final int BITS_TOTAL = 8192;

    private final long[] bitmap = new long[BITS_TOTAL / 64];
    private long latest = -1L;
    private boolean initialized;

    /**
     * @return true if {@code counter} is new and accepted; false if replay or too old
     */
    public synchronized boolean tryAccept(long counter) {
        if (counter < 0L) {
            return false;
        }
        if (!initialized) {
            clear();
            setBit(0);
            latest = counter;
            initialized = true;
            return true;
        }
        if (counter > latest) {
            long diff = counter - latest;
            if (diff >= BITS_TOTAL) {
                clear();
            } else {
                shiftLeft(diff);
            }
            setBit(0);
            latest = counter;
            return true;
        }
        long behind = latest - counter;
        if (behind >= BITS_TOTAL) {
            return false;
        }
        int index = (int) behind;
        if (getBit(index)) {
            return false;
        }
        setBit(index);
        return true;
    }

    public synchronized long latest() {
        return latest;
    }

    /** Shift bits toward higher indices by {@code diff} (vacate low bits). */
    private void shiftLeft(long diff) {
        int words = (int) (diff >>> 6);
        int bits = (int) (diff & 63);
        if (words != 0) {
            for (int i = bitmap.length - 1; i >= 0; i--) {
                int src = i - words;
                bitmap[i] = src >= 0 ? bitmap[src] : 0L;
            }
        }
        if (bits != 0) {
            for (int i = bitmap.length - 1; i > 0; i--) {
                bitmap[i] = (bitmap[i] << bits) | (bitmap[i - 1] >>> (64 - bits));
            }
            bitmap[0] <<= bits;
        }
    }

    private void clear() {
        for (int i = 0; i < bitmap.length; i++) {
            bitmap[i] = 0L;
        }
    }

    private void setBit(int index) {
        bitmap[index >>> 6] |= 1L << (index & 63);
    }

    private boolean getBit(int index) {
        return (bitmap[index >>> 6] & (1L << (index & 63))) != 0;
    }
}
