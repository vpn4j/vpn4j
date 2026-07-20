package com.github.vpn4j.crypto;

import com.github.vpn4j.protocol.NoiseLengths;

import java.util.Arrays;
import java.util.Objects;

/**
 * Fixed-length key material. Defensive copy on construct; {@link #bytes()} returns a copy.
 */
public final class Key {

    private final byte[] bytes;

    public Key(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.length != NoiseLengths.PUBLIC_KEY && bytes.length != NoiseLengths.SYMMETRIC_KEY) {
            throw new IllegalArgumentException("key length must be 32, got " + bytes.length);
        }
        this.bytes = Arrays.copyOf(bytes, bytes.length);
    }

    public int length() {
        return bytes.length;
    }

    public byte[] bytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    public boolean equalsConstantTime(Key other) {
        if (other == null || other.bytes.length != bytes.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < bytes.length; i++) {
            diff |= bytes[i] ^ other.bytes[i];
        }
        return diff == 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Key)) {
            return false;
        }
        return equalsConstantTime((Key) o);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
