package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CidrTest {

    @Test
    void parseIpv4MasksNetwork() throws Exception {
        Cidr c = Cidr.parse("10.1.2.3/16");
        assertEquals(16, c.prefixLen());
        assertEquals(32, c.bitLength());
        assertArrayEquals(InetAddress.getByName("10.1.0.0").getAddress(), c.network());
    }

    @Test
    void parseWithoutPrefixIsHostRoute() throws Exception {
        Cidr c = Cidr.parse("10.0.0.1");
        assertEquals(32, c.prefixLen());
        assertArrayEquals(InetAddress.getByName("10.0.0.1").getAddress(), c.network());
    }

    @Test
    void parseIpv6MasksNetwork() throws Exception {
        Cidr c = Cidr.parse("fd00::1/8");
        assertEquals(8, c.prefixLen());
        assertEquals(128, c.bitLength());
        assertArrayEquals(InetAddress.getByName("fd00::").getAddress(), c.network());
    }

    @Test
    void bitIsMsbFirst() throws Exception {
        byte[] addr = InetAddress.getByName("128.0.0.1").getAddress();
        assertEquals(1, Cidr.bit(addr, 0));
        assertEquals(0, Cidr.bit(addr, 1));
        assertEquals(1, Cidr.bit(addr, 31));
    }

    @Test
    void rejectsBadInput() {
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("not-an-ip/24"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("10.0.0.1/33"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("10.0.0.1/x"));
        assertThrows(IllegalArgumentException.class, () -> new Cidr(new byte[3], 8));
        assertThrows(IllegalArgumentException.class, () -> new Cidr(new byte[4], -1));
    }
}
