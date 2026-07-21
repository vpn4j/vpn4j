package com.github.vpn4j.protocol;

import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertThrows;

class NoiseHandshakeResponseErrorsTest {

    @Test
    void consumeResponseRejectsBadLengthAndType() {
        SecureRandom random = new SecureRandom();
        KeyPair a = X25519.generate(random);
        KeyPair b = X25519.generate(random);
        NoiseHandshake initiator = new NoiseHandshake(a, b.publicKey(), null, random);
        initiator.createInitiation(1);

        assertThrows(IllegalArgumentException.class, () -> initiator.consumeResponse(new byte[10]));

        byte[] wrongType = new byte[MessageSizes.HANDSHAKE_RESPONSE];
        wrongType[0] = (byte) MessageType.DATA.wire();
        assertThrows(IllegalArgumentException.class, () -> initiator.consumeResponse(wrongType));
    }
}
