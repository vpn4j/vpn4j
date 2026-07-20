package com.github.vpn4j.tun;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MemoryTunPortTest {

    @Test
    void injectReadWritePollAndClone() throws Exception {
        MemoryTunPort tun = new MemoryTunPort();
        byte[] fromOs = new byte[] {1, 2, 3, 4};
        tun.injectFromOs(fromOs);
        fromOs[0] = 9;

        byte[] dst = new byte[8];
        assertEquals(4, tun.read(dst, 0, dst.length));
        assertArrayEquals(new byte[] {1, 2, 3, 4, 0, 0, 0, 0}, dst);

        assertEquals(0, tun.read(dst, 0, dst.length));

        byte[] toOs = new byte[] {5, 6, 7};
        tun.write(toOs, 0, toOs.length);
        assertArrayEquals(toOs, tun.pollToOs(1000));
        assertNull(tun.pollToOs(10));
        tun.close();
    }

    @Test
    void partialReadUsesMinLength() {
        MemoryTunPort tun = new MemoryTunPort();
        tun.injectFromOs(new byte[] {1, 2, 3, 4, 5});
        byte[] dst = new byte[8];
        assertEquals(2, tun.read(dst, 1, 2));
        assertEquals(1, dst[1]);
        assertEquals(2, dst[2]);
        tun.close();
    }

    @Test
    void closedRejectsIo() {
        MemoryTunPort tun = new MemoryTunPort();
        tun.close();
        assertThrows(IllegalStateException.class, () -> tun.injectFromOs(new byte[] {1}));
        assertThrows(IllegalStateException.class, () -> tun.read(new byte[4], 0, 4));
        assertThrows(IllegalStateException.class, () -> tun.write(new byte[1], 0, 1));
    }
}
