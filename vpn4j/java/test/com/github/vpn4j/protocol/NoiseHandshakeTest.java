package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NoiseHandshakeTest {

    @Test
    void handshakeDerivesMatchingTransportKeys() {
        SecureRandom random = new SecureRandom();
        KeyPair initiatorId = X25519.generate(random);
        KeyPair responderId = X25519.generate(random);

        NoiseHandshake initiator = new NoiseHandshake(initiatorId, responderId.publicKey(), null, random);
        NoiseHandshake responder = new NoiseHandshake(responderId, initiatorId.publicKey(), null, random);

        byte[] initiation = initiator.createInitiation(0x11111111);
        assertEquals(MessageSizes.HANDSHAKE_INITIATION, initiation.length);
        assertEquals(MessageType.HANDSHAKE_INITIATION, MessageType.fromWire(initiation[0] & 0xff));

        responder.consumeInitiation(initiation, initiatorId.publicKey());
        byte[] response = responder.createResponse(0x22222222);
        assertEquals(MessageSizes.HANDSHAKE_RESPONSE, response.length);

        TransportKeys iKeys = initiator.consumeResponse(response);
        TransportKeys rKeys = responder.deriveTransportKeysAsResponder();

        assertArrayEquals(iKeys.sendingKey().bytes(), rKeys.receivingKey().bytes());
        assertArrayEquals(iKeys.receivingKey().bytes(), rKeys.sendingKey().bytes());
        assertEquals(0x11111111, iKeys.localIndex());
        assertEquals(0x22222222, iKeys.remoteIndex());
        assertEquals(0x22222222, rKeys.localIndex());
        assertEquals(0x11111111, rKeys.remoteIndex());
    }

    @Test
    void matchingPskDerivesKeysMismatchedPskFails() {
        SecureRandom random = new SecureRandom();
        KeyPair initiatorId = X25519.generate(random);
        KeyPair responderId = X25519.generate(random);
        byte[] psk = new byte[32];
        random.nextBytes(psk);

        NoiseHandshake initiator = new NoiseHandshake(initiatorId, responderId.publicKey(), psk, random);
        NoiseHandshake responder = new NoiseHandshake(responderId, initiatorId.publicKey(), psk, random);
        byte[] initiation = initiator.createInitiation(1);
        responder.consumeInitiation(initiation, initiatorId.publicKey());
        byte[] response = responder.createResponse(2);
        TransportKeys iKeys = initiator.consumeResponse(response);
        TransportKeys rKeys = responder.deriveTransportKeysAsResponder();
        assertArrayEquals(iKeys.sendingKey().bytes(), rKeys.receivingKey().bytes());

        byte[] wrongPsk = psk.clone();
        wrongPsk[0] ^= 1;
        NoiseHandshake initiator2 = new NoiseHandshake(initiatorId, responderId.publicKey(), psk, random);
        NoiseHandshake responder2 = new NoiseHandshake(responderId, initiatorId.publicKey(), wrongPsk, random);
        byte[] initiation2 = initiator2.createInitiation(3);
        responder2.consumeInitiation(initiation2, initiatorId.publicKey());
        byte[] response2 = responder2.createResponse(4);
        assertThrows(IllegalStateException.class, () -> initiator2.consumeResponse(response2));
    }

    @Test
    void consumeInitiationRejectsBadMac1LengthTypeAndStatic() {
        SecureRandom random = new SecureRandom();
        KeyPair initiatorId = X25519.generate(random);
        KeyPair responderId = X25519.generate(random);
        NoiseHandshake initiator = new NoiseHandshake(initiatorId, responderId.publicKey(), null, random);
        NoiseHandshake responder = new NoiseHandshake(responderId, initiatorId.publicKey(), null, random);

        assertThrows(IllegalArgumentException.class, () -> responder.consumeInitiation(new byte[10], initiatorId.publicKey()));

        byte[] initiation = initiator.createInitiation(7);
        initiation[0] = 4;
        assertThrows(IllegalArgumentException.class, () -> responder.consumeInitiation(initiation, initiatorId.publicKey()));

        byte[] initiation2 = initiator.createInitiation(8);
        initiation2[initiation2.length - 32] ^= 1; // flip mac1
        assertThrows(IllegalArgumentException.class, () -> responder.consumeInitiation(initiation2, initiatorId.publicKey()));

        NoiseHandshake initiator3 = new NoiseHandshake(initiatorId, responderId.publicKey(), null, random);
        NoiseHandshake responder3 = new NoiseHandshake(responderId, initiatorId.publicKey(), null, random);
        byte[] initiation3 = initiator3.createInitiation(9);
        KeyPair other = X25519.generate(random);
        assertThrows(
                IllegalArgumentException.class,
                () -> responder3.consumeInitiation(initiation3, other.publicKey()));
    }

    @Test
    void roleAndIndexGuards() {
        SecureRandom random = new SecureRandom();
        KeyPair initiatorId = X25519.generate(random);
        KeyPair responderId = X25519.generate(random);
        NoiseHandshake initiator = new NoiseHandshake(initiatorId, responderId.publicKey(), null, random);
        NoiseHandshake responder = new NoiseHandshake(responderId, initiatorId.publicKey(), null, random);

        byte[] initiation = initiator.createInitiation(0x11111111);
        assertThrows(IllegalStateException.class, () -> initiator.createResponse(1));
        assertThrows(IllegalStateException.class, () -> initiator.deriveTransportKeysAsResponder());

        responder.consumeInitiation(initiation, initiatorId.publicKey());
        assertThrows(IllegalStateException.class, () -> responder.consumeResponse(new byte[MessageSizes.HANDSHAKE_RESPONSE]));

        byte[] response = responder.createResponse(0x22222222);
        // wrong echo index
        response[8] ^= 1;
        // mac1 must be recomputed after tampering would fail first — rebuild clean response then patch after mac
        NoiseHandshake initiator2 = new NoiseHandshake(initiatorId, responderId.publicKey(), null, random);
        NoiseHandshake responder2 = new NoiseHandshake(responderId, initiatorId.publicKey(), null, random);
        byte[] initiation2 = initiator2.createInitiation(0x11111111);
        responder2.consumeInitiation(initiation2, initiatorId.publicKey());
        byte[] response2 = responder2.createResponse(0x22222222);
        // Corrupt echo index then leave mac1 invalid → mac1 invalid
        response2[8] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> initiator2.consumeResponse(response2));
    }

    @Test
    void cookieMac2AndCheckMac1() {
        SecureRandom random = new SecureRandom();
        KeyPair initiatorId = X25519.generate(random);
        KeyPair responderId = X25519.generate(random);
        NoiseHandshake initiator = new NoiseHandshake(initiatorId, responderId.publicKey(), null, random);

        byte[] without = initiator.createInitiation(1, null);
        assertTrue(NoiseHandshake.checkMac1(without, responderId.publicKey()));
        byte[] mac2 = Arrays.copyOfRange(without, without.length - 16, without.length);
        assertArrayEquals(new byte[16], mac2);

        byte[] cookie = new byte[16];
        random.nextBytes(cookie);
        NoiseHandshake initiator2 = new NoiseHandshake(initiatorId, responderId.publicKey(), null, random);
        byte[] with = initiator2.createInitiation(2, cookie);
        assertTrue(NoiseHandshake.checkMac1(with, responderId.publicKey()));
        assertTrue(CookieChecker.verifyMac2(with, cookie));
        assertFalse(Arrays.equals(new byte[16], NoiseHandshake.mac1Of(with)));
    }
}
