package com.github.vpn4j.protocol;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Parsed CIDR (IPv4 or IPv6).
 */
public final class Cidr {

    private final byte[] network;
    private final int prefixLen;

    public Cidr(byte[] network, int prefixLen) {
        this.network = Arrays.copyOf(network, network.length);
        this.prefixLen = prefixLen;
        if (network.length != 4 && network.length != 16) {
            throw new IllegalArgumentException("address must be IPv4 or IPv6");
        }
        int max = network.length * 8;
        if (prefixLen < 0 || prefixLen > max) {
            throw new IllegalArgumentException("prefix out of range");
        }
        maskInPlace(this.network, prefixLen);
    }

    public byte[] network() {
        return Arrays.copyOf(network, network.length);
    }

    public int prefixLen() {
        return prefixLen;
    }

    public int bitLength() {
        return network.length * 8;
    }

    public static Cidr parse(String cidr) {
        Objects.requireNonNull(cidr, "cidr");
        int slash = cidr.indexOf('/');
        String host = slash < 0 ? cidr.trim() : cidr.substring(0, slash).trim();
        try {
            InetAddress addr = InetAddress.getByName(host);
            byte[] raw = addr.getAddress();
            int max = raw.length * 8;
            int prefix = slash < 0 ? max : Integer.parseInt(cidr.substring(slash + 1).trim());
            return new Cidr(raw, prefix);
        } catch (UnknownHostException | NumberFormatException e) {
            throw new IllegalArgumentException("bad cidr: " + cidr, e);
        }
    }

    static void maskInPlace(byte[] addr, int prefixLen) {
        int full = prefixLen / 8;
        int rem = prefixLen % 8;
        for (int i = full + (rem > 0 ? 1 : 0); i < addr.length; i++) {
            addr[i] = 0;
        }
        if (rem > 0 && full < addr.length) {
            int mask = 0xff << (8 - rem);
            addr[full] = (byte) (addr[full] & mask);
        }
    }

    /** Bit {@code index} of the address, MSB-first (0 = highest bit of byte 0). */
    public static int bit(byte[] addr, int index) {
        int b = addr[index >>> 3] & 0xff;
        return (b >>> (7 - (index & 7))) & 1;
    }
}
