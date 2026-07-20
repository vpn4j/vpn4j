package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Key;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class TransportKeysTest {

    @Test
    void accessors() {
        byte[] send = new byte[32];
        Arrays.fill(send, (byte) 1);
        byte[] recv = new byte[32];
        Arrays.fill(recv, (byte) 2);
        Key sk = new Key(send);
        Key rk = new Key(recv);
        TransportKeys keys = new TransportKeys(sk, rk, 11, 22);
        assertSame(sk, keys.sendingKey());
        assertSame(rk, keys.receivingKey());
        assertEquals(11, keys.localIndex());
        assertEquals(22, keys.remoteIndex());
    }
}
