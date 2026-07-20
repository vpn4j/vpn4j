package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Bytes;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataPacketTest {

    @Test
    void sealAndOpenRoundTripWithHeaderLayout() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x11);
        byte[] plain = new byte[] {1, 2, 3, 4, 5};
        int receiver = 0x0a0b0c0d;
        long counter = 42L;

        byte[] msg = DataPacket.seal(key, receiver, counter, plain);
        assertEquals(MessageType.DATA.wire(), msg[0] & 0xff);
        assertEquals(receiver, Bytes.getIntLe(msg, 4));
        assertTrue(msg.length >= MessageSizes.DATA_MINIMUM);

        DataPacket.Opened opened = DataPacket.open(key, msg);
        assertEquals(receiver, opened.receiverIndex());
        assertEquals(counter, opened.counter());
        // open returns padded plaintext (WG padding zeros)
        assertArrayEquals(PacketPadding.pad(plain), opened.plaintext());
    }

    @Test
    void nullPlaintextSealsEmptyKeepalive() {
        byte[] key = new byte[32];
        byte[] msg = DataPacket.seal(key, 1, 0L, null);
        assertEquals(MessageSizes.DATA_MINIMUM, msg.length);
        assertEquals(0, DataPacket.open(key, msg).plaintext().length);
    }

    @Test
    void openRejectsShortOrWrongType() {
        byte[] key = new byte[32];
        assertThrows(IllegalArgumentException.class, () -> DataPacket.open(key, new byte[8]));
        byte[] bad = DataPacket.seal(key, 1, 0L, new byte[0]);
        bad[0] = 1;
        assertThrows(IllegalArgumentException.class, () -> DataPacket.open(key, bad));
    }

    @Test
    void openFailsWithWrongKey() {
        byte[] key = new byte[32];
        byte[] other = new byte[32];
        Arrays.fill(other, (byte) 2);
        byte[] msg = DataPacket.seal(key, 1, 0L, new byte[] {9});
        assertThrows(IllegalStateException.class, () -> DataPacket.open(other, msg));
    }
}
