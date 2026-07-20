package com.github.vpn4j.config;

import com.github.vpn4j.crypto.Key;
import com.github.vpn4j.crypto.Keys;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Minimal WireGuard conf parser ({@code [Interface]} / {@code [Peer]}).
 */
public final class WgConfigParser {

    private WgConfigParser() {
    }

    public static WgConfig parseFile(Path path) throws IOException {
        return parse(Files.newBufferedReader(path, StandardCharsets.UTF_8));
    }

    public static WgConfig parseString(String text) throws IOException {
        return parse(new StringReader(text));
    }

    public static WgConfig parse(Reader reader) throws IOException {
        WgConfig.Builder iface = WgConfig.builder();
        PeerConfig.Builder peer = null;
        boolean inInterface = false;
        boolean inPeer = false;

        try (BufferedReader br = reader instanceof BufferedReader
                ? (BufferedReader) reader
                : new BufferedReader(reader)) {
            String line;
            while ((line = br.readLine()) != null) {
                line = stripComment(line).trim();
                if (line.isEmpty()) {
                    continue;
                }
                if (line.startsWith("[") && line.endsWith("]")) {
                    if (inPeer && peer != null) {
                        iface.addPeer(peer.build());
                        peer = null;
                    }
                    String section = line.substring(1, line.length() - 1).trim().toLowerCase(Locale.ROOT);
                    inInterface = "interface".equals(section);
                    inPeer = "peer".equals(section);
                    if (inPeer) {
                        peer = null; // set on PublicKey
                    }
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq <= 0) {
                    throw new IllegalArgumentException("bad line: " + line);
                }
                String key = line.substring(0, eq).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(eq + 1).trim();

                if (inInterface) {
                    applyInterface(iface, key, value);
                } else if (inPeer) {
                    peer = applyPeer(peer, key, value);
                } else {
                    throw new IllegalArgumentException("key outside section: " + key);
                }
            }
            if (inPeer && peer != null) {
                iface.addPeer(peer.build());
            }
        }
        return iface.build();
    }

    private static void applyInterface(WgConfig.Builder iface, String key, String value) {
        switch (key) {
            case "privatekey":
                iface.privateKeyBase64(value);
                break;
            case "listenport":
                iface.listenPort(Integer.parseInt(value));
                break;
            case "address":
                for (String part : value.split(",")) {
                    String cidr = part.trim();
                    if (!cidr.isEmpty()) {
                        iface.addAddress(cidr);
                    }
                }
                break;
            case "name":
            case "interfacename":
                iface.interfaceName(value);
                break;
            default:
                // Ignore unknown Interface keys (DNS, Table, etc.) for now.
                break;
        }
    }

    private static PeerConfig.Builder applyPeer(PeerConfig.Builder peer, String key, String value) {
        switch (key) {
            case "publickey":
                Key pub = Keys.fromBase64(value);
                if (peer == null) {
                    peer = PeerConfig.builder(pub);
                } else {
                    throw new IllegalArgumentException("PublicKey already set for peer");
                }
                break;
            case "presharedkey":
                requirePeer(peer).presharedKey(Keys.fromBase64(value));
                break;
            case "endpoint":
                requirePeer(peer).endpoint(WgConfig.parseEndpoint(value));
                break;
            case "allowedips":
                PeerConfig.Builder b = requirePeer(peer);
                for (String part : value.split(",")) {
                    String cidr = part.trim();
                    if (!cidr.isEmpty()) {
                        b.addAllowedIp(cidr);
                    }
                }
                break;
            case "persistentkeepalive":
                requirePeer(peer).persistentKeepaliveSeconds(Integer.parseInt(value));
                break;
            default:
                break;
        }
        return peer;
    }

    private static PeerConfig.Builder requirePeer(PeerConfig.Builder peer) {
        if (peer == null) {
            throw new IllegalArgumentException("Peer PublicKey must come first");
        }
        return peer;
    }

    private static String stripComment(String line) {
        int hash = line.indexOf('#');
        int semi = line.indexOf(';');
        int cut = -1;
        if (hash >= 0) {
            cut = hash;
        }
        if (semi >= 0 && (cut < 0 || semi < cut)) {
            cut = semi;
        }
        return cut < 0 ? line : line.substring(0, cut);
    }
}
