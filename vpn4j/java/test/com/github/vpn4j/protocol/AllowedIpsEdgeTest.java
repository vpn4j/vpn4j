package com.github.vpn4j.protocol;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AllowedIpsEdgeTest {

    @Test
    void lookupRejectsNullAndOddLength() {
        AllowedIpsTable<String> table = new AllowedIpsTable<>();
        table.insert("10.0.0.0/8", "a");
        assertNull(table.lookup((byte[]) null));
        assertNull(table.lookup(new byte[5]));
        assertNull(table.lookup((InetAddress) null));
    }

    @Test
    void destinationAddressIgnoresBadPackets() {
        assertNull(AllowedIpsTable.destinationAddress(null, 0));
        assertNull(AllowedIpsTable.destinationAddress(new byte[] {0x40}, 1)); // v4 but too short
        byte[] v6short = new byte[10];
        v6short[0] = 0x60;
        assertNull(AllowedIpsTable.destinationAddress(v6short, v6short.length));
    }

    @Test
    void insertRequiresValue() {
        AllowedIpsTable<String> table = new AllowedIpsTable<>();
        assertThrows(NullPointerException.class, () -> table.insert("10.0.0.0/8", null));
    }

    @Test
    void cidrPartialByteMask() throws Exception {
        Cidr c = Cidr.parse("10.1.255.255/12");
        assertEquals(12, c.prefixLen());
        // /12 keeps top 4 bits of second byte: 10.0.0.0
        assertEquals(InetAddress.getByName("10.0.0.0"), InetAddress.getByAddress(c.network()));
    }
}
