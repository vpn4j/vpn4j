package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AllowedIpsTableTest {

    @Test
    void longestPrefixWins() throws Exception {
        AllowedIpsTable<String> table = new AllowedIpsTable<>();
        table.insert("10.0.0.0/8", "wide");
        table.insert("10.1.0.0/16", "mid");
        table.insert("10.1.2.3/32", "exact");

        assertEquals("exact", table.lookup(InetAddress.getByName("10.1.2.3")));
        assertEquals("mid", table.lookup(InetAddress.getByName("10.1.9.9")));
        assertEquals("wide", table.lookup(InetAddress.getByName("10.9.9.9")));
        assertNull(table.lookup(InetAddress.getByName("11.0.0.1")));
    }

    @Test
    void ipv6Prefix() throws Exception {
        AllowedIpsTable<String> table = new AllowedIpsTable<>();
        table.insert("fd00::/8", "ula");
        table.insert("fd12:3456::/32", "site");
        assertEquals("site", table.lookup(InetAddress.getByName("fd12:3456::1")));
        assertEquals("ula", table.lookup(InetAddress.getByName("fd99::1")));
    }

    @Test
    void packetDestinationLookup() {
        AllowedIpsTable<String> table = new AllowedIpsTable<>();
        table.insert("192.168.1.0/24", "lan");
        byte[] pkt = new byte[20];
        pkt[0] = 0x45;
        pkt[16] = (byte) 192;
        pkt[17] = (byte) 168;
        pkt[18] = 1;
        pkt[19] = 50;
        assertEquals("lan", table.lookupDestination(pkt, pkt.length));
    }
}
