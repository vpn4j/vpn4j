package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Bytes;
import com.github.vpn4j.crypto.ChaCha20Poly1305;

/**
 * WireGuard transport data message (type 4) — seal / open.
 */
public final class DataPacket {

    private DataPacket() {
    }

    public static byte[] seal(byte[] sendingKey, int receiverIndex, long counter, byte[] plaintext) {
        byte[] padded = PacketPadding.pad(plaintext == null ? new byte[0] : plaintext);
        byte[] encrypted = ChaCha20Poly1305.seal(sendingKey, counter, padded, new byte[0]);
        byte[] msg = new byte[MessageSizes.DATA_HEADER + encrypted.length];
        msg[0] = (byte) MessageType.DATA.wire();
        Bytes.putIntLe(msg, 4, receiverIndex);
        Bytes.putLongLe(msg, 8, counter);
        System.arraycopy(encrypted, 0, msg, MessageSizes.DATA_HEADER, encrypted.length);
        return msg;
    }

    public static Opened open(byte[] receivingKey, byte[] msg) {
        if (msg == null || msg.length < MessageSizes.DATA_MINIMUM) {
            throw new IllegalArgumentException("data packet too short");
        }
        if (MessageType.fromWire(msg[0] & 0xff) != MessageType.DATA) {
            throw new IllegalArgumentException("not a data packet");
        }
        int receiverIndex = Bytes.getIntLe(msg, 4);
        long counter = getLongLe(msg, 8);
        byte[] ciphertext = Bytes.slice(msg, MessageSizes.DATA_HEADER, msg.length - MessageSizes.DATA_HEADER);
        byte[] plain = ChaCha20Poly1305.open(receivingKey, counter, ciphertext, new byte[0]);
        return new Opened(receiverIndex, counter, plain);
    }

    private static long getLongLe(byte[] src, int offset) {
        long v = 0L;
        for (int i = 0; i < 8; i++) {
            v |= ((long) (src[offset + i] & 0xff)) << (8 * i);
        }
        return v;
    }

    public static final class Opened {
        private final int receiverIndex;
        private final long counter;
        private final byte[] plaintext;

        public Opened(int receiverIndex, long counter, byte[] plaintext) {
            this.receiverIndex = receiverIndex;
            this.counter = counter;
            this.plaintext = plaintext;
        }

        public int receiverIndex() {
            return receiverIndex;
        }

        public long counter() {
            return counter;
        }

        public byte[] plaintext() {
            return plaintext;
        }
    }
}
