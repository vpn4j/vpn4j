package com.github.vpn4j.crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Optional;

import javax.crypto.KeyAgreement;

/**
 * Curve25519 ECDH via JDK X25519, with WireGuard-style 32-byte little-endian keys.
 */
public final class X25519 {

    private X25519() {
    }

    public static KeyPair generate(SecureRandom random) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("X25519");
            g.initialize(NamedParameterSpec.X25519, random);
            java.security.KeyPair jdk = g.generateKeyPair();
            byte[] priv = privateToRaw((XECPrivateKey) jdk.getPrivate());
            byte[] pub = publicToRaw((XECPublicKey) jdk.getPublic());
            return new KeyPair(new Key(priv), new Key(pub));
        } catch (GeneralSecurityRuntime e) {
            throw e;
        } catch (Exception e) {
            throw new GeneralSecurityRuntime("X25519 generate failed", e);
        }
    }

    public static Key publicFromPrivate(Key privateKey) {
        try {
            PrivateKey priv = privateFromRaw(privateKey.bytes());
            // Derive public by agreeing with the basepoint via KeyPair regeneration path:
            KeyFactory kf = KeyFactory.getInstance("X25519");
            // JDK does not expose scalar*base directly; use KeyAgreement with known base.
            // Convert private → XECPrivateKey and obtain public via KeyPairGenerator trick:
            // Compute DH(priv, basepoint) where basepoint u=9.
            byte[] base = new byte[32];
            base[0] = 9;
            byte[] shared = sharedSecret(privateKey, new Key(base));
            // For X25519, DH(priv, 9) IS the public key.
            return new Key(shared);
        } catch (Exception e) {
            throw new GeneralSecurityRuntime("X25519 publicFromPrivate failed", e);
        }
    }

    public static byte[] sharedSecret(Key privateKey, Key peerPublic) {
        try {
            PrivateKey priv = privateFromRaw(privateKey.bytes());
            PublicKey pub = publicFromRaw(peerPublic.bytes());
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(priv);
            ka.doPhase(pub, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new GeneralSecurityRuntime("X25519 DH failed", e);
        }
    }

    private static PrivateKey privateFromRaw(byte[] le32) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("X25519");
        // XECPrivateKeySpec expects the scalar bytes (little-endian for X25519)
        return kf.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, le32.clone()));
    }

    private static PublicKey publicFromRaw(byte[] le32) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("X25519");
        BigInteger u = fromLittleEndian(le32);
        return kf.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
    }

    private static byte[] privateToRaw(XECPrivateKey key) {
        Optional<byte[]> scalar = key.getScalar();
        if (scalar.isEmpty()) {
            throw new GeneralSecurityRuntime("X25519 private scalar unavailable");
        }
        byte[] s = scalar.get();
        if (s.length != 32) {
            byte[] out = new byte[32];
            System.arraycopy(s, 0, out, 0, Math.min(32, s.length));
            return out;
        }
        return s.clone();
    }

    private static byte[] publicToRaw(XECPublicKey key) {
        return toLittleEndian(key.getU());
    }

    private static byte[] toLittleEndian(BigInteger u) {
        byte[] be = u.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(32, be.length);
        System.arraycopy(be, be.length - copy, out, 32 - copy, copy);
        reverse(out);
        return out;
    }

    private static BigInteger fromLittleEndian(byte[] le) {
        byte[] be = le.clone();
        reverse(be);
        return new BigInteger(1, be);
    }

    private static void reverse(byte[] a) {
        for (int i = 0; i < a.length / 2; i++) {
            byte t = a[i];
            a[i] = a[a.length - 1 - i];
            a[a.length - 1 - i] = t;
        }
    }

    public static final class GeneralSecurityRuntime extends RuntimeException {
        public GeneralSecurityRuntime(String message) {
            super(message);
        }

        public GeneralSecurityRuntime(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
