package com.github.vpn4j.cli;

import com.github.vpn4j.config.PeerConfig;
import com.github.vpn4j.config.WgConfig;
import com.github.vpn4j.config.WgConfigParser;
import com.github.vpn4j.config.WgConfigs;
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
        int code = run(args);
        if (code != 0) {
            System.exit(code);
        }
    }

    /** Dispatch command; returns process exit code (0 = ok). */
    static int run(String[] args) throws Exception {
        String cmd = args.length == 0 ? "help" : args[0];
        switch (cmd) {
            case "smoke":
                smoke();
                return 0;
            case "genkey":
                genkey();
                return 0;
            case "pubkey":
                pubkey();
                return 0;
            case "up":
                up(args, upMaxPumps());
                return 0;
            case "help":
            case "-h":
            case "--help":
                help();
                return 0;
            default:
                System.err.println("unknown command: " + cmd);
                help();
                return 2;
        }
    }

    static void help() {
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
        up(args, upMaxPumps());
    }

    /** {@code -Dvpn4j.cli.up.maxPumps=N} bounds pumps for tests; unset means forever. */
    static int upMaxPumps() {
        String prop = System.getProperty("vpn4j.cli.up.maxPumps");
        if (prop == null || prop.isEmpty()) {
            return -1;
        }
        return Integer.parseInt(prop);
    }

    /**
     * Bring up from wg-style config.
     *
     * @param maxPumps number of pump iterations; negative means forever (CLI default)
     */
    static void up(String[] args, int maxPumps) throws Exception {
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
            if (maxPumps < 0) {
                Runtime.getRuntime().addShutdownHook(new Thread(engine::close));
            }
            int pumps = 0;
            while (maxPumps < 0 || pumps < maxPumps) {
                engine.pumpOnce();
                pumps++;
                try {
                    Thread.sleep(10L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            engine.close();
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

        try (UdpCarrier carrierA = UdpCarrier.bind(0);
                UdpCarrier carrierB = UdpCarrier.bind(0)) {
            int portA = ((InetSocketAddress) carrierA.channel().getLocalAddress()).getPort();
            int portB = ((InetSocketAddress) carrierB.channel().getLocalAddress()).getPort();
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
