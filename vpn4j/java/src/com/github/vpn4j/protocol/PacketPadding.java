package com.github.vpn4j.protocol;

/**
 * WireGuard transport padding — pad plaintext to a multiple of 16 (empty stays empty).
 */
public final class PacketPadding {

    private PacketPadding() {
    }

    public static byte[] pad(byte[] plaintext) {
        if (plaintext == null || plaintext.length == 0) {
            return new byte[0];
        }
        int rem = plaintext.length % MessageSizes.PADDING_MULTIPLE;
        if (rem == 0) {
            return plaintext.clone();
        }
        int pad = MessageSizes.PADDING_MULTIPLE - rem;
        byte[] out = new byte[plaintext.length + pad];
        System.arraycopy(plaintext, 0, out, 0, plaintext.length);
        return out;
    }
}
