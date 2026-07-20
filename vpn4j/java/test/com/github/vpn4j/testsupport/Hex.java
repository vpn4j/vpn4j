package com.github.vpn4j.testsupport;

/** Hex decode helper for crypto / protocol KATs. */
public final class Hex {

    private Hex() {
    }

    public static byte[] decode(String hex) {
        String s = hex.replaceAll("\\s+", "");
        if ((s.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
