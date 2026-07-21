package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TransportSessionRejectTest {

    @Test
    void sealExhaustedAndOpenRejectsHugeCounter() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair a = X25519.generate(random);
        KeyPair b = X25519.generate(random);
        NoiseHandshake initiator = new NoiseHandshake(a, b.publicKey(), null, random);
        NoiseHandshake responder = new NoiseHandshake(b, a.publicKey(), null, random);
        byte[] init = initiator.createInitiation(1);
        responder.consumeInitiation(init, a.publicKey());
        byte[] resp = responder.createResponse(2);
        TransportKeys iKeys = initiator.consumeResponse(resp);
        TransportSession send = new TransportSession(iKeys);
        TransportSession recv = new TransportSession(responder.deriveTransportKeysAsResponder());

        Field counter = TransportSession.class.getDeclaredField("sendCounter");
        counter.setAccessible(true);
        counter.setLong(send, TransportSession.REJECT_AFTER_MESSAGES);
        assertThrows(IllegalStateException.class, () -> send.seal(new byte[] {1}));

        byte[] aged = DataPacket.seal(
                iKeys.sendingKey().bytes(),
                iKeys.remoteIndex(),
                TransportSession.REJECT_AFTER_MESSAGES,
                new byte[] {9});
        assertNull(recv.open(aged));
    }
}
