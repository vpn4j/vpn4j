package com.github.vpn4j.config;

import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.Keys;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WgConfigParserTest {

    @Test
    void parsesInterfaceAndPeer() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        KeyPair peer = X25519.generate(random);
        String conf = ""
                + "[Interface]\n"
                + "PrivateKey = " + Keys.toBase64(self.privateKey()) + "\n"
                + "ListenPort = 51820\n"
                + "Address = 10.0.0.1/24\n"
                + "Name = wgtest0\n"
                + "\n"
                + "[Peer]\n"
                + "PublicKey = " + Keys.toBase64(peer.publicKey()) + "\n"
                + "AllowedIPs = 10.0.0.0/24, 192.168.1.0/24\n"
                + "Endpoint = 203.0.113.1:51820\n"
                + "PersistentKeepalive = 25\n";

        WgConfig cfg = WgConfigParser.parseString(conf);
        assertEquals(51820, cfg.listenPort());
        assertEquals("wgtest0", cfg.interfaceName());
        assertEquals(1, cfg.addresses().size());
        assertEquals("10.0.0.1/24", cfg.addresses().get(0));
        assertTrue(cfg.identity().publicKey().equalsConstantTime(self.publicKey()));
        assertEquals(1, cfg.peers().size());
        PeerConfig p = cfg.peers().get(0);
        assertTrue(p.publicKey().equalsConstantTime(peer.publicKey()));
        assertEquals(2, p.allowedIps().size());
        assertNotNull(p.endpoint());
        assertEquals(51820, p.endpoint().getPort());
        assertEquals(25, p.persistentKeepaliveSeconds());
    }

    @Test
    void parsesIpv6Endpoint() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        KeyPair peer = X25519.generate(random);
        String conf = ""
                + "[Interface]\n"
                + "PrivateKey = " + Keys.toBase64(self.privateKey()) + "\n"
                + "[Peer]\n"
                + "PublicKey = " + Keys.toBase64(peer.publicKey()) + "\n"
                + "Endpoint = [2001:db8::1]:51820\n"
                + "AllowedIPs = ::/0\n";
        WgConfig cfg = WgConfigParser.parseString(conf);
        assertEquals(InetAddress.getByName("2001:db8::1"), cfg.peers().get(0).endpoint().getAddress());
        assertEquals(51820, cfg.peers().get(0).endpoint().getPort());
    }

    @Test
    void ignoresCommentsBlanksUnknownKeysAndParsesPsk() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        KeyPair peer = X25519.generate(random);
        KeyPair psk = X25519.generate(random);
        String conf = ""
                + "# top comment\n"
                + "[Interface]\n"
                + "PrivateKey = " + Keys.toBase64(self.privateKey()) + " ; trailing\n"
                + "DNS = 1.1.1.1\n"
                + "InterfaceName = custom0\n"
                + "\n"
                + "[Peer]\n"
                + "PublicKey = " + Keys.toBase64(peer.publicKey()) + "\n"
                + "PresharedKey = " + Keys.toBase64(psk.privateKey()) + "\n"
                + "AllowedIPs = 10.0.0.0/24\n";
        WgConfig cfg = WgConfigParser.parseString(conf);
        assertEquals("custom0", cfg.interfaceName());
        assertNotNull(cfg.peers().get(0).presharedKey());
        assertTrue(cfg.peers().get(0).presharedKey().equalsConstantTime(psk.privateKey()));
    }

    @Test
    void parsesMultiplePeers() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        KeyPair p1 = X25519.generate(random);
        KeyPair p2 = X25519.generate(random);
        String conf = ""
                + "[Interface]\n"
                + "PrivateKey = " + Keys.toBase64(self.privateKey()) + "\n"
                + "Address = 10.0.0.1/24,  fd00::1/64\n"
                + "[Peer]\n"
                + "PublicKey = " + Keys.toBase64(p1.publicKey()) + "\n"
                + "AllowedIPs = 10.0.0.2/32\n"
                + "[Peer]\n"
                + "PublicKey = " + Keys.toBase64(p2.publicKey()) + "\n"
                + "AllowedIPs = 10.0.0.3/32\n";
        WgConfig cfg = WgConfigParser.parseString(conf);
        assertEquals(2, cfg.addresses().size());
        assertEquals(2, cfg.peers().size());
    }

    @Test
    void parseErrors() {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        KeyPair peer = X25519.generate(random);
        String priv = Keys.toBase64(self.privateKey());
        String pub = Keys.toBase64(peer.publicKey());

        assertThrows(IllegalArgumentException.class, () -> WgConfigParser.parseString("PrivateKey = " + priv + "\n"));
        assertThrows(IllegalArgumentException.class, () -> WgConfigParser.parseString("[Interface]\nbadline\n"));
        assertThrows(
                IllegalArgumentException.class,
                () -> WgConfigParser.parseString("[Peer]\nAllowedIPs = 0.0.0.0/0\n"));
        assertThrows(
                IllegalArgumentException.class,
                () -> WgConfigParser.parseString(
                        "[Interface]\nPrivateKey = " + priv + "\n[Peer]\nPublicKey = " + pub + "\nPublicKey = " + pub
                                + "\n"));
        assertThrows(IllegalArgumentException.class, () -> WgConfig.builder().build());
        assertThrows(
                IllegalArgumentException.class,
                () -> WgConfig.builder().privateKeyBase64(priv).listenPort(70000).build());
        assertNull(WgConfig.parseEndpoint(""));
        assertThrows(IllegalArgumentException.class, () -> WgConfig.parseEndpoint("no-port"));
        assertThrows(IllegalArgumentException.class, () -> WgConfig.parseEndpoint("[::1]51820"));
    }

    @Test
    void toDeviceConfigDefaultsToTun() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        WgConfig cfg = WgConfig.builder().privateKey(self.privateKey()).listenPort(1).build();
        assertEquals(TransportMode.TUN, cfg.toDeviceConfig(null).transportMode());
        assertEquals(1, cfg.toDeviceConfig(TransportMode.TUN).listenPort());
    }

    @Test
    void peerKeepaliveNegativeRejected() {
        Key pub = X25519.generate(new SecureRandom()).publicKey();
        assertThrows(
                IllegalArgumentException.class,
                () -> PeerConfig.builder(pub).persistentKeepaliveSeconds(-1).build());
    }
}
