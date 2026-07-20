package com.github.vpn4j.cli;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.config.WgConfig;
import com.github.vpn4j.config.WgConfigParser;
import com.github.vpn4j.config.WgConfigs;
import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.KeyPair;
import com.github.vpn4j.crypto.Keys;
import com.github.vpn4j.crypto.X25519;
import com.github.vpn4j.device.NativeTunPort;
import com.github.vpn4j.device.TunDevice;
import com.github.vpn4j.engine.DeviceEngine;
import com.github.vpn4j.engine.PeerEngine;
import com.github.vpn4j.nativeapi.NativeBootstrap;
import com.github.vpn4j.transport.UdpCarrier;
import com.github.vpn4j.tun.MemoryTunPort;
import com.github.vpn4j.tun.TunPort;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * vpn4j CLI — {@code smoke}, {@code genkey}, {@code pubkey}, {@code up --config}.
 */
public final class Vpn4jCli {

    public static void main(String[] args) throws Exception {
        String cmd = args.length == 0 ? "help" : args[0];
        switch (cmd) {
            case "smoke":
                smoke();
                break;
            case "genkey":
                genkey();
                break;
            case "pubkey":
                pubkey();
                break;
            case "up":
                up(args);
                break;
            case "help":
            case "-h":
            case "--help":
                help();
                break;
            default:
                System.err.println("unknown command: " + cmd);
                help();
                System.exit(2);
        }
    }

    private static void help() {
        System.out.println("usage:");
        System.out.println("  vpn4j-cli smoke");
        System.out.println("  vpn4j-cli genkey");
        System.out.println("  vpn4j-cli pubkey < privatekey");
        System.out.println("  vpn4j-cli up --config <file> [--tun] [--under-load]");
    }

    static void genkey() {
        KeyPair pair = X25519.generate(new SecureRandom());
        System.out.println(Keys.toBase64(pair.privateKey()));
    }

    static void pubkey() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line = in.readLine();
        if (line == null || line.trim().isEmpty()) {
            throw new IllegalArgumentException("expected private key on stdin");
        }
        KeyPair pair = Keys.keyPairFromPrivate(Keys.fromBase64(line.trim()));
        System.out.println(Keys.toBase64(pair.publicKey()));
    }

    static void up(String[] args) throws Exception {
        Path configPath = null;
        boolean useTun = false;
        boolean underLoad = false;
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            if ("--config".equals(a) || "-c".equals(a)) {
                configPath = Path.of(args[++i]);
            } else if ("--tun".equals(a)) {
                useTun = true;
            } else if ("--under-load".equals(a)) {
                underLoad = true;
            } else {
                throw new IllegalArgumentException("unknown flag: " + a);
            }
        }
        if (configPath == null) {
            throw new IllegalArgumentException("--config required");
        }

        WgConfig cfg = WgConfigParser.parseFile(configPath);
        System.out.println("loaded " + configPath + " peers=" + cfg.peers().size()
                + " listen=" + cfg.listenPort()
                + " if=" + cfg.interfaceName());

        TunPort tun;
        TunDevice nativeTun = null;
        if (useTun) {
            NativeBootstrap.load();
            nativeTun = TunDevice.open(cfg.interfaceName());
            tun = new NativeTunPort(nativeTun);
            System.out.println("TUN open: " + cfg.interfaceName());
        } else {
            tun = new MemoryTunPort();
            System.out.println("using MemoryTunPort (pass --tun for real TUN; needs CAP_NET_ADMIN + VPN4J_NATIVE_LIBRARY)");
        }

        try (UdpCarrier carrier = UdpCarrier.bind(cfg.listenPort())) {
            DeviceEngine engine = WgConfigs.deviceEngine(cfg, carrier, tun);
            if (underLoad) {
                engine.setUnderLoad(true);
            }
            for (PeerConfig peer : cfg.peers()) {
                if (peer.endpoint() != null) {
                    engine.initiate(peer.publicKey());
                    System.out.println("initiated -> " + Keys.toBase64(peer.publicKey()).substring(0, 8) + "...");
                }
            }
            System.out.println("pumping (Ctrl+C to stop)");
            Runtime.getRuntime().addShutdownHook(new Thread(engine::close));
            while (true) {
                engine.pumpOnce();
                Thread.sleep(10L);
            }
        } finally {
            tun.close();
            if (nativeTun != null) {
                nativeTun.close();
            }
        }
    }

    static void smoke() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair aId = X25519.generate(random);
        KeyPair bId = X25519.generate(random);

        int portB = 51821;
        int portA = 51820;

        try (UdpCarrier carrierA = UdpCarrier.bind(portA);
                UdpCarrier carrierB = UdpCarrier.bind(portB)) {
            MemoryTunPort tunA = new MemoryTunPort();
            MemoryTunPort tunB = new MemoryTunPort();

            PeerEngine engineA = new PeerEngine(
                    aId,
                    PeerConfig.builder(bId.publicKey())
                            .endpoint(new InetSocketAddress("127.0.0.1", portB))
                            .build(),
                    carrierA,
                    tunA,
                    random);
            PeerEngine engineB = new PeerEngine(
                    bId,
                    PeerConfig.builder(aId.publicKey())
                            .endpoint(new InetSocketAddress("127.0.0.1", portA))
                            .build(),
                    carrierB,
                    tunB,
                    random);

            System.out.println("vpn4j smoke: UDP handshake " + portA + " <-> " + portB);
            engineA.initiate();

            long deadline = System.currentTimeMillis() + 5_000L;
            while (System.currentTimeMillis() < deadline
                    && !(engineA.established() && engineB.established())) {
                engineB.pumpOnce();
                engineA.pumpOnce();
            }
            if (!engineA.established() || !engineB.established()) {
                throw new IllegalStateException("handshake did not complete");
            }
            System.out.println("handshake ok");

            byte[] payload = "vpn4j-smoke".getBytes(StandardCharsets.US_ASCII);
            tunA.injectFromOs(payload);
            deadline = System.currentTimeMillis() + 5_000L;
            byte[] got = null;
            while (System.currentTimeMillis() < deadline && got == null) {
                engineA.pumpOnce();
                engineB.pumpOnce();
                got = tunB.pollToOs(50);
            }
            if (got == null || !Arrays.equals(payload, Arrays.copyOf(got, payload.length))) {
                throw new IllegalStateException("data path failed");
            }
            System.out.println("data ok (" + payload.length + " bytes)");
            System.out.println("smoke passed");

            engineA.close();
            engineB.close();
            tunA.close();
            tunB.close();
        }
    }

    private Vpn4jCli() {
    }
}
