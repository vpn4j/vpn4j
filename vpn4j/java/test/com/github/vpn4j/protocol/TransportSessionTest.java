package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TransportSessionTest {

    @Test
    void sealOpenRoundTripAndReplay() {
        SecureRandom random = new SecureRandom();
        KeyPair initiatorId = X25519.generate(random);
        KeyPair responderId = X25519.generate(random);

        NoiseHandshake initiator = new NoiseHandshake(initiatorId, responderId.publicKey(), null, random);
        NoiseHandshake responder = new NoiseHandshake(responderId, initiatorId.publicKey(), null, random);

        byte[] initiation = initiator.createInitiation(1);
        responder.consumeInitiation(initiation, initiatorId.publicKey());
        byte[] response = responder.createResponse(2);
        TransportSession iSess = new TransportSession(initiator.consumeResponse(response));
        TransportSession rSess = new TransportSession(responder.deriveTransportKeysAsResponder());

        byte[] plain = "hello-vpn4j".getBytes(StandardCharsets.US_ASCII);
        byte[] packet = iSess.seal(plain);
        assertEquals(MessageType.DATA, MessageType.fromWire(packet[0] & 0xff));
        assertTrue(packet.length >= MessageSizes.DATA_MINIMUM);

        byte[] opened = rSess.open(packet);
        // padding may extend; inner content starts with plaintext
        assertTrue(opened.length >= plain.length);
        assertArrayEquals(plain, Arrays.copyOf(opened, plain.length));

        assertNull(rSess.open(packet));

        byte[] keepAlive = iSess.seal(new byte[0]);
        byte[] empty = rSess.open(keepAlive);
        assertEquals(0, empty.length);
    }
}
