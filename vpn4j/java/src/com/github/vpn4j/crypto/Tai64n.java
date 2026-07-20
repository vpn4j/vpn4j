package com.github.vpn4j.crypto;

/**
 * TAI64N timestamp (12 bytes) as used by WireGuard.
 */
public final class Tai64n {

    /** Approximate TAI-UTC leap-second offset (adequate for replay ordering). */
    private static final long TAI_OFFSET_SECONDS = 37L;

    private Tai64n() {
    }

    public static byte[] now() {
        long millis = System.currentTimeMillis();
        long seconds = millis / 1000L + TAI_OFFSET_SECONDS;
        int nanos = (int) ((millis % 1000L) * 1_000_000L);
        return of(seconds, nanos);
    }

    public static byte[] of(long taiSeconds, int nanos) {
        byte[] out = new byte[12];
        Bytes.putLongBe(out, 0, taiSeconds);
        Bytes.putIntBe(out, 8, nanos);
        return out;
    }
}
