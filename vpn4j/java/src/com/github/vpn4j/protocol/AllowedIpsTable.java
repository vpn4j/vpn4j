package com.github.vpn4j.protocol;

import java.net.InetAddress;
import java.util.Objects;

/**
 * Longest-prefix-match allowed-IPs table (binary trie). Clean-room, not a paste of WireGuard C.
 *
 * @param <T> peer / route value
 */
public final class AllowedIpsTable<T> {

    private final Node<T> root4 = new Node<>();
    private final Node<T> root6 = new Node<>();

    public void insert(String cidr, T value) {
        insert(Cidr.parse(cidr), value);
    }

    public void insert(Cidr cidr, T value) {
        Objects.requireNonNull(value, "value");
        Node<T> node = cidr.bitLength() == 32 ? root4 : root6;
        byte[] net = cidr.network();
        for (int i = 0; i < cidr.prefixLen(); i++) {
            int b = Cidr.bit(net, i);
            Node<T> next = node.child(b);
            if (next == null) {
                next = new Node<>();
                node.setChild(b, next);
            }
            node = next;
        }
        node.value = value;
        node.hasValue = true;
    }

    public T lookup(byte[] address) {
        if (address == null) {
            return null;
        }
        Node<T> node;
        int bits;
        if (address.length == 4) {
            node = root4;
            bits = 32;
        } else if (address.length == 16) {
            node = root6;
            bits = 128;
        } else {
            return null;
        }
        T best = null;
        if (node.hasValue) {
            best = node.value;
        }
        for (int i = 0; i < bits; i++) {
            int b = Cidr.bit(address, i);
            node = node.child(b);
            if (node == null) {
                break;
            }
            if (node.hasValue) {
                best = node.value;
            }
        }
        return best;
    }

    public T lookup(InetAddress address) {
        return address == null ? null : lookup(address.getAddress());
    }

    /** Destination lookup for a raw IP packet (v4/v6). */
    public T lookupDestination(byte[] packet, int length) {
        InetAddress dst = destinationAddress(packet, length);
        return lookup(dst);
    }

    public static InetAddress destinationAddress(byte[] packet, int length) {
        if (packet == null || length < 1) {
            return null;
        }
        int version = (packet[0] >>> 4) & 0x0f;
        try {
            if (version == 4 && length >= 20) {
                byte[] addr = new byte[] {packet[16], packet[17], packet[18], packet[19]};
                return InetAddress.getByAddress(addr);
            }
            if (version == 6 && length >= 40) {
                byte[] addr = new byte[16];
                System.arraycopy(packet, 24, addr, 0, 16);
                return InetAddress.getByAddress(addr);
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private static final class Node<T> {
        Node<T> child0;
        Node<T> child1;
        T value;
        boolean hasValue;

        Node<T> child(int bit) {
            return bit == 0 ? child0 : child1;
        }

        void setChild(int bit, Node<T> node) {
            if (bit == 0) {
                child0 = node;
            } else {
                child1 = node;
            }
        }
    }
}
