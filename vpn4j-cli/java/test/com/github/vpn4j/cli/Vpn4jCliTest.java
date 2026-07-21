package com.github.vpn4j.cli;

import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.Keys;
import com.github.vpn4j.crypto.X25519;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Vpn4jCliTest {

    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;
    private final InputStream originalIn = System.in;

    @AfterEach
    void restoreStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
        System.setIn(originalIn);
        System.clearProperty("vpn4j.cli.up.maxPumps");
    }

    @Test
    void genkeyAndPubkeyRoundTrip() throws Exception {
        ByteArrayOutputStream genOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(genOut, true, StandardCharsets.UTF_8));
        Vpn4jCli.genkey();
        String privB64 = genOut.toString(StandardCharsets.UTF_8).trim();
        assertEquals(44, privB64.length());

        ByteArrayOutputStream pubOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(pubOut, true, StandardCharsets.UTF_8));
        System.setIn(new ByteArrayInputStream((privB64 + "\n").getBytes(StandardCharsets.UTF_8)));
        Vpn4jCli.pubkey();
        String pubB64 = pubOut.toString(StandardCharsets.UTF_8).trim();

        KeyPair expected = Keys.keyPairFromPrivate(Keys.fromBase64(privB64));
        assertEquals(Keys.toBase64(expected.publicKey()), pubB64);
    }

    @Test
    void pubkeyRequiresStdin() {
        System.setIn(new ByteArrayInputStream(new byte[0]));
        assertThrows(IllegalArgumentException.class, Vpn4jCli::pubkey);
    }

    @Test
    void upRequiresConfig() {
        Exception ex = assertThrows(IllegalArgumentException.class, () -> Vpn4jCli.up(new String[] {"up"}));
        assertTrue(ex.getMessage().contains("--config"));
    }

    @Test
    void upRejectsUnknownFlag() {
        assertThrows(
                IllegalArgumentException.class,
                () -> Vpn4jCli.up(new String[] {"up", "--config", "x.conf", "--nope"}));
    }

    @Test
    void runHelpAndUnknown() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        assertEquals(0, Vpn4jCli.run(new String[] {"help"}));
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("vpn4j-cli smoke"));

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        assertEquals(2, Vpn4jCli.run(new String[] {"not-a-command"}));
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("unknown command"));
    }

    @Test
    void runGenkey() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        assertEquals(0, Vpn4jCli.run(new String[] {"genkey"}));
        assertEquals(44, out.toString(StandardCharsets.UTF_8).trim().length());
    }

    @Test
    void smokePassesOverLocalhostUdp() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        assertEquals(0, Vpn4jCli.run(new String[] {"smoke"}));
        String text = out.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("handshake ok"));
        assertTrue(text.contains("smoke passed"));
    }

    @Test
    void upMemoryTunPumps(@TempDir Path dir) throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        KeyPair peer = X25519.generate(random);
        Path conf = dir.resolve("peer.conf");
        Files.writeString(
                conf,
                "[Interface]\n"
                        + "PrivateKey = " + Keys.toBase64(self.privateKey()) + "\n"
                        + "ListenPort = 0\n"
                        + "Name = vpn4jtest0\n"
                        + "[Peer]\n"
                        + "PublicKey = " + Keys.toBase64(peer.publicKey()) + "\n"
                        + "AllowedIPs = 10.0.0.2/32\n"
                        + "Endpoint = 127.0.0.1:9\n",
                StandardCharsets.UTF_8);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        Vpn4jCli.up(new String[] {"up", "--config", conf.toString(), "--under-load"}, 3);
        String text = out.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("MemoryTunPort"));
        assertTrue(text.contains("initiated"));
        assertTrue(text.contains("pumping"));
    }

    @Test
    void upShortFlagConfig(@TempDir Path dir) throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        Path conf = dir.resolve("solo.conf");
        Files.writeString(
                conf,
                "[Interface]\nPrivateKey = " + Keys.toBase64(self.privateKey()) + "\nListenPort = 0\n",
                StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        Vpn4jCli.up(new String[] {"up", "-c", conf.toString()}, 1);
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("peers=0"));
    }

    @Test
    void runEmptyArgsHelpAliasesAndPubkey() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        assertEquals(0, Vpn4jCli.run(new String[] {}));
        assertEquals(0, Vpn4jCli.run(new String[] {"-h"}));
        assertEquals(0, Vpn4jCli.run(new String[] {"--help"}));

        KeyPair pair = X25519.generate(new SecureRandom());
        System.setIn(new ByteArrayInputStream(
                (Keys.toBase64(pair.privateKey()) + "\n").getBytes(StandardCharsets.UTF_8)));
        out.reset();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        assertEquals(0, Vpn4jCli.run(new String[] {"pubkey"}));
        assertEquals(Keys.toBase64(pair.publicKey()), out.toString(StandardCharsets.UTF_8).trim());
    }

    @Test
    void runUpHonorsMaxPumpsProperty(@TempDir Path dir) throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        Path conf = dir.resolve("p.conf");
        Files.writeString(
                conf,
                "[Interface]\nPrivateKey = " + Keys.toBase64(self.privateKey()) + "\nListenPort = 0\n",
                StandardCharsets.UTF_8);
        System.setProperty("vpn4j.cli.up.maxPumps", "2");
        assertEquals(2, Vpn4jCli.upMaxPumps());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        assertEquals(0, Vpn4jCli.run(new String[] {"up", "--config", conf.toString()}));
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("MemoryTunPort"));
    }

    @Test
    void privateConstructor() throws Exception {
        var ctor = Vpn4jCli.class.getDeclaredConstructor();
        ctor.setAccessible(true);
        assertTrue(ctor.newInstance() instanceof Vpn4jCli);
    }

    @Test
    void upArgsWrapperAndEmptyMaxPumpsProperty(@TempDir Path dir) throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        Path conf = dir.resolve("w.conf");
        Files.writeString(
                conf,
                "[Interface]\nPrivateKey = " + Keys.toBase64(self.privateKey()) + "\nListenPort = 0\n",
                StandardCharsets.UTF_8);
        System.setProperty("vpn4j.cli.up.maxPumps", "");
        assertEquals(-1, Vpn4jCli.upMaxPumps());
        System.setProperty("vpn4j.cli.up.maxPumps", "1");
        Vpn4jCli.up(new String[] {"up", "--config", conf.toString()}); // wrapper → upMaxPumps()
    }

    @Test
    void upTunFailsFastWithoutNative(@TempDir Path dir) throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        Path conf = dir.resolve("tun.conf");
        Files.writeString(
                conf,
                "[Interface]\nPrivateKey = " + Keys.toBase64(self.privateKey()) + "\nListenPort = 0\n",
                StandardCharsets.UTF_8);
        System.clearProperty("vpn4j.native.library");
        assertThrows(
                Exception.class,
                () -> Vpn4jCli.up(new String[] {"up", "--config", conf.toString(), "--tun"}, 1));
    }

    @Test
    void upForeverLoopStopsOnInterrupt(@TempDir Path dir) throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair self = X25519.generate(random);
        Path conf = dir.resolve("forever.conf");
        Files.writeString(
                conf,
                "[Interface]\nPrivateKey = " + Keys.toBase64(self.privateKey()) + "\nListenPort = 0\n",
                StandardCharsets.UTF_8);
        Thread t = new Thread(() -> {
            try {
                Vpn4jCli.up(new String[] {"up", "--config", conf.toString()}, -1);
            } catch (Exception ignored) {
                // interrupted teardown
            }
        });
        t.setDaemon(true);
        t.start();
        Thread.sleep(40L);
        t.interrupt();
        t.join(3000L);
        assertTrue(!t.isAlive());
    }
}
