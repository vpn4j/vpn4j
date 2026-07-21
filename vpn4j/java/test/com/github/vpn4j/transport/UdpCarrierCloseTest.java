package com.github.vpn4j.transport;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UdpCarrierCloseTest {

    @Test
    void closePreventsFurtherIo() throws Exception {
        UdpCarrier a = UdpCarrier.bind(0);
        UdpCarrier b = UdpCarrier.bind(0);
        InetSocketAddress bAddr = (InetSocketAddress) b.channel().getLocalAddress();
        a.close();
        assertThrows(
                ClosedChannelException.class,
                () -> a.send(new byte[] {1}, new InetSocketAddress("127.0.0.1", bAddr.getPort())));
        assertTrue(b.channel().isOpen());
        b.close();
    }
}
