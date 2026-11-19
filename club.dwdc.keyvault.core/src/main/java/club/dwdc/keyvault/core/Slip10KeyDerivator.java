package club.dwdc.keyvault.core;

import org.bitcoinj.wallet.DeterministicSeed;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * SLIP-10 key derivation (API 0.6.0, B3): one root per curve, selected by
 * {@link Alg}.
 *
 * <ul>
 *   <li>Master: {@code I = HMAC-SHA512(key = alg.label(), data = seed)};
 *       {@code IL} is the key, {@code IR} the chain code. For the Weierstrass
 *       curves an invalid {@code IL} (0 or ≥ n) restarts with {@code seed := I}.</li>
 *   <li>Hardened child: {@code I = HMAC-SHA512(c, 0x00 ‖ k ‖ ser32(i))}.</li>
 *   <li>Non-hardened child (secp256k1, P-256 only):
 *       {@code I = HMAC-SHA512(c, serP(point(k)) ‖ ser32(i))}, serP compressed.</li>
 *   <li>secp256k1, P-256: {@code k' = IL + k mod n}; if {@code IL ≥ n} or
 *       {@code k' = 0}, retry with {@code I = HMAC-SHA512(c, 0x01 ‖ IR ‖ ser32(i))}.</li>
 *   <li>Ed25519: {@code k' = IL}, and a non-hardened index is refused.</li>
 * </ul>
 *
 * For secp256k1 this is BIP-32, so Nostr, realm, avatar xpub and transport keys
 * are the same as in 0.5.x ({@code Slip10EquivalenceTest}).
 */
public final class Slip10KeyDerivator implements KeyDerivator {

    /** A derived extended private key: 32-byte key and 32-byte chain code. */
    public record Node(byte[] key, byte[] chainCode) {
    }

    private static final int HARDENED = 0x80000000;

    private static final ECDomainParameters SECP256K1 = domainOf("secp256k1");
    private static final ECDomainParameters P256 = domainOf("secp256r1");

    private final byte[] seed;

    /** Create from a binary seed (BIP-39 output, 16–64 bytes). */
    public Slip10KeyDerivator(byte[] seed) {
        if (seed == null || seed.length < 16 || seed.length > 64) {
            throw new IllegalArgumentException("seed must be 16-64 bytes");
        }
        this.seed = seed.clone();
    }

    /** Create from a BIP-39 mnemonic and passphrase (empty for none). */
    public static Slip10KeyDerivator fromMnemonic(String mnemonic, String passphrase) {
        return new Slip10KeyDerivator(DeterministicSeed.ofMnemonic(mnemonic, passphrase).getSeedBytes());
    }

    /** The elliptic-curve domain for a Weierstrass {@code alg}, or {@code null} (Ed25519, reserved). */
    static ECDomainParameters domain(Alg alg) {
        return switch (alg) {
            case SECP256K1 -> SECP256K1;
            case P256 -> P256;
            default -> null;
        };
    }

    @Override
    public byte[] derive(Alg alg, int... path) {
        return deriveNode(alg, path).key();
    }

    /**
     * Derive the extended private key at {@code path} under the root of {@code alg}.
     *
     * @throws IllegalArgumentException for a reserved {@code alg}, or a
     *         non-hardened index under {@link Alg#ED25519}
     */
    public Node deriveNode(Alg alg, int... path) {
        if (alg == null || !alg.isSupported()) {
            throw new IllegalArgumentException("no SLIP-10 root for " + alg);
        }
        ECDomainParameters curve = domain(alg);
        if (curve == null) {
            for (int index : path) {
                if ((index & HARDENED) == 0) {
                    throw new IllegalArgumentException("ed25519 is hardened-only");
                }
            }
        }

        Node node = master(alg, curve);
        for (int index : path) {
            node = curve == null ? childEd25519(node, index) : childWeierstrass(node, index, curve);
        }
        return node;
    }

    // ── Master ───────────────────────────────────────────────────────────

    private Node master(Alg alg, ECDomainParameters curve) {
        byte[] key = alg.label().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] data = seed;
        while (true) {
            byte[] i = hmacSha512(key, data);
            byte[] il = Arrays.copyOfRange(i, 0, 32);
            byte[] ir = Arrays.copyOfRange(i, 32, 64);
            if (curve == null) {
                return new Node(il, ir);
            }
            BigInteger k = new BigInteger(1, il);
            if (k.signum() != 0 && k.compareTo(curve.getN()) < 0) {
                return new Node(il, ir);
            }
            data = i;
        }
    }

    // ── Children ─────────────────────────────────────────────────────────

    private static Node childEd25519(Node parent, int index) {
        byte[] i = hmacSha512(parent.chainCode(), concat(new byte[]{0}, parent.key(), ser32(index)));
        return new Node(Arrays.copyOfRange(i, 0, 32), Arrays.copyOfRange(i, 32, 64));
    }

    private static Node childWeierstrass(Node parent, int index, ECDomainParameters curve) {
        BigInteger n = curve.getN();
        BigInteger kPar = new BigInteger(1, parent.key());
        byte[] data = (index & HARDENED) != 0
                ? concat(new byte[]{0}, parent.key(), ser32(index))
                : concat(curve.getG().multiply(kPar).normalize().getEncoded(true), ser32(index));

        byte[] i = hmacSha512(parent.chainCode(), data);
        while (true) {
            byte[] il = Arrays.copyOfRange(i, 0, 32);
            byte[] ir = Arrays.copyOfRange(i, 32, 64);
            BigInteger parsed = new BigInteger(1, il);
            BigInteger child = parsed.add(kPar).mod(n);
            if (parsed.compareTo(n) < 0 && child.signum() != 0) {
                return new Node(to32Bytes(child), ir);
            }
            i = hmacSha512(parent.chainCode(), concat(new byte[]{1}, ir, ser32(index)));
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static ECDomainParameters domainOf(String name) {
        var p = CustomNamedCurves.getByName(name);
        return new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
    }

    private static byte[] hmacSha512(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA512 not available", e);
        }
    }

    private static byte[] ser32(int index) {
        return ByteBuffer.allocate(4).putInt(index).array();
    }

    static byte[] to32Bytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        if (bytes.length > 32) {
            return Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
        }
        byte[] padded = new byte[32];
        System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
        return padded;
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }
}
