package com.github.vpn4j.device;

import com.github.vpn4j.config.DeviceConfig;
import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.config.TransportMode;
import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DeviceTest {

    @Test
    void addPeerAndClose() {
        KeyPair identity = KeyPair.generateEphemeral(new SecureRandom());
        DeviceConfig cfg = DeviceConfig.builder().transportMode(TransportMode.TUN).build();
        Device device = new Device(cfg, identity);
        byte[] peerPub = new byte[32];
        peerPub[0] = 1;
        device.addPeer(PeerConfig.builder(new Key(peerPub)).addAllowedIp("10.0.0.2/32").build());
        assertEquals(1, device.peers().size());
        assertEquals(TransportMode.TUN, device.transportMode());
        assertEquals(identity, device.identity());
        assertEquals(null, device.tun());
        device.close();
        device.close(); // idempotent
        PeerConfig late = PeerConfig.builder(new Key(peerPub)).build();
        assertThrows(IllegalStateException.class, new AddPeer(device, late));
    }

    private static final class AddPeer implements org.junit.jupiter.api.function.Executable {
        private final Device device;
        private final PeerConfig peer;

        AddPeer(Device device, PeerConfig peer) {
            this.device = device;
            this.peer = peer;
        }

        @Override
        public void execute() {
            device.addPeer(peer);
        }
    }
}
