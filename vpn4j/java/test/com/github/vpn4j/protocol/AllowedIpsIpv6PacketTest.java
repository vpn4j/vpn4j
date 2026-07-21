package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AllowedIpsIpv6PacketTest {

    @Test
    void ipv6DestinationLookup() throws Exception {
        AllowedIpsTable<String> table = new AllowedIpsTable<>();
        table.insert("fd00::/8", "ula");
        table.insert("fd12:3456::/32", "site");

        byte[] pkt = new byte[40];
        pkt[0] = 0x60; // IPv6
        byte[] dst = InetAddress.getByName("fd12:3456::99").getAddress();
        System.arraycopy(dst, 0, pkt, 24, 16);
        assertEquals("site", table.lookupDestination(pkt, pkt.length));

        byte[] other = InetAddress.getByName("fd99::1").getAddress();
        System.arraycopy(other, 0, pkt, 24, 16);
        assertEquals("ula", table.lookupDestination(pkt, pkt.length));

        assertNull(table.lookupDestination(new byte[] {0x60}, 1));
        assertEquals(
                InetAddress.getByName("fd12:3456::99"),
                AllowedIpsTable.destinationAddress(buildV6("fd12:3456::99"), 40));
    }

    private static byte[] buildV6(String dst) throws Exception {
        byte[] pkt = new byte[40];
        pkt[0] = 0x60;
        System.arraycopy(InetAddress.getByName(dst).getAddress(), 0, pkt, 24, 16);
        return pkt;
    }
}
