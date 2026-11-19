package club.dwdc.keyvault.core;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Arrays;

/**
 * The software KeyVault, API 0.6.0 ({@code doc/api-0.6.0.md}).
 *
 * <p>Keys are derived with SLIP-10 ({@link Slip10KeyDerivator}) under the root of
 * the {@code alg} parameter; the name is kept from the BIP-32 era for callers.
 *
 * <p>Checks run in this order, so every refusal has one well-defined error:
 * <ol>
 *   <li>path shorter than 5 levels → {@code ERR_INVALID_PATH}</li>
 *   <li>reserved {@code alg} → {@code ERR_UNSUPPORTED_ALGORITHM}</li>
 *   <li>{@code EXPORT} → {@code ERR_INVALID_PATH} on a non-hardened path,
 *       otherwise {@code ERR_UNSUPPORTED_ALGORITHM} (B5)</li>
 *   <li>{@code fn} other than GET_PUBLIC_KEY, SIGN, KEY_AGREEMENT
 *       ({@code DECAPSULATE}, 16+, unknown) → {@code ERR_UNSUPPORTED_FUNCTION}</li>
 *   <li>unknown or reserved {@code option} → {@code ERR_UNSUPPORTED_ALGORITHM}</li>
 *   <li>binding check ({@link Binding}) → {@code ERR_INVALID_PATH}</li>
 *   <li>non-hardened level under Ed25519 → {@code ERR_INVALID_PATH}</li>
 *   <li>payload length → {@code ERR_INVALID_PAYLOAD}</li>
 *   <li>the operation; arithmetic failure → {@code ERR_CRYPTO_FAILURE}</li>
 * </ol>
 */
public class Bip32KeyVault implements KeyVault {

    private static final int H = 0x80000000;

    private static final EdDSAParameterSpec ED25519_SPEC =
            EdDSANamedCurveTable.getByName("Ed25519");

    private final Slip10KeyDerivator derivator;

    /** Create from BIP-39 mnemonic (no passphrase). */
    public Bip32KeyVault(String mnemonic) {
        this(mnemonic, "");
    }

    /** Create from BIP-39 mnemonic with optional passphrase. */
    public Bip32KeyVault(String mnemonic, String passphrase) {
        this.derivator = Slip10KeyDerivator.fromMnemonic(mnemonic, passphrase);
    }

    /** Create from a binary seed (16–64 bytes). */
    public Bip32KeyVault(byte[] seed) {
        this.derivator = new Slip10KeyDerivator(seed);
    }

    @Override
    public VaultResult execute(Alg alg, int fn, int option, byte[] payload, int... path) {
        if (path == null || path.length < 5) {
            return VaultResult.error(VaultResult.ERR_INVALID_PATH);
        }
        if (alg == null || !alg.isSupported()) {
            return VaultResult.error(VaultResult.ERR_UNSUPPORTED_ALGORITHM);
        }
        if (fn == FN_EXPORT) {
            return VaultResult.error(allHardened(path)
                    ? VaultResult.ERR_UNSUPPORTED_ALGORITHM
                    : VaultResult.ERR_INVALID_PATH);
        }
        if (fn != FN_GET_PUBLIC_KEY && fn != FN_SIGN && fn != FN_KEY_AGREEMENT) {
            return VaultResult.error(VaultResult.ERR_UNSUPPORTED_FUNCTION);
        }
        if (!implemented(alg, fn, option)) {
            return VaultResult.error(VaultResult.ERR_UNSUPPORTED_ALGORITHM);
        }
        if (Binding.check(alg, fn, option, path) != VaultResult.OK) {
            return VaultResult.error(VaultResult.ERR_INVALID_PATH);
        }
        if (alg == Alg.ED25519 && !allHardened(path)) {
            return VaultResult.error(VaultResult.ERR_INVALID_PATH);
        }
        if (!payloadLengthOk(alg, fn, payload)) {
            return VaultResult.error(VaultResult.ERR_INVALID_PAYLOAD);
        }

        Slip10KeyDerivator.Node node = derivator.deriveNode(alg, path);
        try {
            return switch (fn) {
                case FN_GET_PUBLIC_KEY -> VaultResult.ok(publicKey(alg, node.key()), node.chainCode());
                case FN_SIGN -> sign(alg, option, node.key(), payload);
                default -> keyAgreement(alg, node.key(), payload);
            };
        } finally {
            Arrays.fill(node.key(), (byte) 0);
        }
    }

    // ── Scheme table ─────────────────────────────────────────────────────

    /** Whether {@code (alg, fn, option)} is implemented. Reserved options are not. */
    static boolean implemented(Alg alg, int fn, int option) {
        return switch (alg) {
            case SECP256K1 -> fn == FN_KEY_AGREEMENT
                    ? option == OPT_DEFAULT
                    : option == OPT_SECP256K1_SCHNORR || option == OPT_SECP256K1_ECDSA;
            case ED25519, P256 -> option == OPT_DEFAULT;
            default -> false;
        };
    }

    /** Exact payload lengths per {@code (alg, fn)} (section 5). */
    static boolean payloadLengthOk(Alg alg, int fn, byte[] payload) {
        int len = payload == null ? -1 : payload.length;
        return switch (fn) {
            case FN_GET_PUBLIC_KEY -> len <= 0;
            case FN_SIGN -> alg == Alg.ED25519 ? len >= 0 : len == 32;
            case FN_KEY_AGREEMENT -> switch (alg) {
                case SECP256K1 -> len == 32 || len == 33;
                case ED25519 -> len == 32;
                case P256 -> len == 33 || len == 65;
                default -> false;
            };
            default -> false;
        };
    }

    private static boolean allHardened(int[] path) {
        for (int index : path) {
            if ((index & H) == 0) {
                return false;
            }
        }
        return true;
    }

    // ── GET_PUBLIC_KEY ───────────────────────────────────────────────────

    /**
     * SECP256K1: 33-byte compressed point. ED25519: 32-byte RFC 8032 public key.
     * P256: 65-byte SEC1 uncompressed point (KeyMaster builds the SPKI and the
     * PKCS#11 {@code CKA_EC_POINT} from it).
     */
    private static byte[] publicKey(Alg alg, byte[] key) {
        return switch (alg) {
            case ED25519 -> new EdDSAPrivateKeySpec(key, ED25519_SPEC).getA().toByteArray();
            case SECP256K1 -> point(alg, key).getEncoded(true);
            default -> point(alg, key).getEncoded(false);
        };
    }

    private static ECPoint point(Alg alg, byte[] key) {
        return Slip10KeyDerivator.domain(alg).getG().multiply(new BigInteger(1, key)).normalize();
    }

    // ── SIGN ─────────────────────────────────────────────────────────────

    private static VaultResult sign(Alg alg, int option, byte[] key, byte[] payload) {
        return switch (alg) {
            case ED25519 -> ed25519Sign(key, payload);
            case SECP256K1 -> option == OPT_SECP256K1_ECDSA
                    ? ecdsaSign(Slip10KeyDerivator.domain(alg), key, payload, true)
                    : schnorrSign(key, payload);
            default -> ecdsaSign(Slip10KeyDerivator.domain(alg), key, payload, false);
        };
    }

    /**
     * BIP-340 Schnorr signature over secp256k1.
     * Deterministic signing (aux randomness = 32 zero bytes).
     *
     * @param seed    32-byte private key
     * @param message 32-byte message hash
     * @return 64-byte signature (R.x || s)
     */
    private static VaultResult schnorrSign(byte[] seed, byte[] message) {
        try {
            ECDomainParameters curve = Slip10KeyDerivator.domain(Alg.SECP256K1);
            BigInteger n = curve.getN();
            ECPoint G = curve.getG();

            BigInteger d = new BigInteger(1, seed);
            ECPoint P = G.multiply(d).normalize();
            byte[] px = bigIntTo32Bytes(P.getXCoord().toBigInteger());

            // If P.y is odd, negate d
            BigInteger dAdj = P.getYCoord().toBigInteger().testBit(0)
                    ? n.subtract(d) : d;

            // Deterministic nonce: k = tagged_hash("BIP0340/nonce", t || px || m) mod n
            byte[] aux = new byte[32];
            byte[] t = xorBytes(bigIntTo32Bytes(dAdj), taggedHash("BIP0340/aux", aux));
            byte[] nonceInput = concat(t, px, message);
            byte[] kHash = taggedHash("BIP0340/nonce", nonceInput);
            BigInteger k = new BigInteger(1, kHash).mod(n);
            if (k.equals(BigInteger.ZERO)) {
                return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
            }

            ECPoint R = G.multiply(k).normalize();
            if (R.getYCoord().toBigInteger().testBit(0)) {
                k = n.subtract(k);
            }
            byte[] rx = bigIntTo32Bytes(R.getXCoord().toBigInteger());

            // Challenge: e = tagged_hash("BIP0340/challenge", rx || px || m) mod n
            byte[] eHash = taggedHash("BIP0340/challenge", concat(rx, px, message));
            BigInteger e = new BigInteger(1, eHash).mod(n);

            // s = (k + e * dAdj) mod n
            BigInteger s = k.add(e.multiply(dAdj)).mod(n);

            return VaultResult.ok(concat(rx, bigIntTo32Bytes(s)));
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    /**
     * Ed25519 signature using net.i2p.crypto.eddsa.
     *
     * @param seed    32-byte Ed25519 seed (the SLIP-10 ed25519 key)
     * @param message raw message bytes (Ed25519 hashes internally)
     * @return 64-byte Ed25519 signature
     */
    private static VaultResult ed25519Sign(byte[] seed, byte[] message) {
        try {
            EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(seed, ED25519_SPEC);
            EdDSAPrivateKey privKey = new EdDSAPrivateKey(privSpec);
            Signature sig = new EdDSAEngine(MessageDigest.getInstance(ED25519_SPEC.getHashAlgorithm()));
            sig.initSign(privKey);
            sig.update(message);
            return VaultResult.ok(sig.sign());
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    /**
     * ECDSA over a 32-byte digest; the caller hashes. RFC 6979 deterministic nonce
     * (HMAC-SHA-256), then low-S: {@code s > n/2 → n − s}.
     *
     * @param withRecoveryId true for secp256k1 option 2: append {@code v}, the
     *                       recovery id (0 or 1) of the normalised signature
     * @return {@code r ‖ s} (64 bytes), or {@code r ‖ s ‖ v} (65 bytes)
     */
    static VaultResult ecdsaSign(ECDomainParameters curve, byte[] key, byte[] digest, boolean withRecoveryId) {
        try {
            BigInteger d = new BigInteger(1, key);
            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
            signer.init(true, new ECPrivateKeyParameters(d, curve));
            BigInteger[] rs = signer.generateSignature(digest);
            BigInteger r = rs[0];
            BigInteger s = lowS(rs[1], curve.getN());
            byte[] rsBytes = concat(bigIntTo32Bytes(r), bigIntTo32Bytes(s));
            if (!withRecoveryId) {
                return VaultResult.ok(rsBytes);
            }
            ECPoint q = curve.getG().multiply(d).normalize();
            for (int v = 0; v <= 1; v++) {
                ECPoint recovered = recover(curve, r, s, v, digest);
                if (recovered != null && recovered.equals(q)) {
                    return VaultResult.ok(concat(rsBytes, new byte[]{(byte) v}));
                }
            }
            // r ≥ p − n would need recovery ids 2 and 3, which this layout does not carry.
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    /** Low-S normalisation (BIP-62 / SEC1 malleability rule). */
    static BigInteger lowS(BigInteger s, BigInteger n) {
        return s.compareTo(n.shiftRight(1)) > 0 ? n.subtract(s) : s;
    }

    /**
     * ECDSA public key recovery (SEC1 4.1.6) for recovery id 0 or 1:
     * {@code R = (r, y with parity v)}, {@code Q = r⁻¹ (sR − eG)}.
     *
     * @return the recovered point, or {@code null} if {@code r} is not an x-coordinate
     */
    static ECPoint recover(ECDomainParameters curve, BigInteger r, BigInteger s, int v, byte[] digest) {
        BigInteger n = curve.getN();
        byte[] compressed = new byte[33];
        compressed[0] = (byte) (v == 0 ? 0x02 : 0x03);
        System.arraycopy(bigIntTo32Bytes(r), 0, compressed, 1, 32);
        ECPoint bigR;
        try {
            bigR = curve.getCurve().decodePoint(compressed);
        } catch (IllegalArgumentException notOnCurve) {
            return null;
        }
        BigInteger e = new BigInteger(1, digest);
        BigInteger rInv = r.modInverse(n);
        ECPoint q = bigR.multiply(s).subtract(curve.getG().multiply(e)).multiply(rInv).normalize();
        return q.isInfinity() ? null : q;
    }

    // ── KEY_AGREEMENT ────────────────────────────────────────────────────

    private static VaultResult keyAgreement(Alg alg, byte[] key, byte[] peer) {
        return switch (alg) {
            case ED25519 -> x25519(key, peer);
            case SECP256K1 -> ecdhX(Slip10KeyDerivator.domain(alg), key,
                    peer.length == 32 ? concat(new byte[]{0x02}, peer) : peer);
            default -> ecdhX(Slip10KeyDerivator.domain(alg), key, peer);
        };
    }

    /**
     * ECDH, shared secret = x-coordinate of {@code d · peer}. The peer point is
     * decoded and validated on the curve (SEC1 compressed or uncompressed);
     * an invalid point or an infinite result is {@code ERR_CRYPTO_FAILURE}.
     */
    static VaultResult ecdhX(ECDomainParameters curve, byte[] key, byte[] peerEncoded) {
        try {
            ECPoint peer = curve.getCurve().decodePoint(peerEncoded);
            if (peer.isInfinity() || !peer.isValid()) {
                return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
            }
            ECPoint shared = peer.multiply(new BigInteger(1, key)).normalize();
            if (shared.isInfinity()) {
                return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
            }
            return VaultResult.ok(bigIntTo32Bytes(shared.getXCoord().toBigInteger()));
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    /**
     * X25519 key agreement: derive the X25519 private key from the Ed25519 seed
     * (SHA-512, first 32 bytes, clamped), then compute the shared secret.
     */
    private static VaultResult x25519(byte[] seed, byte[] peer) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-512").digest(seed);
            byte[] x25519Seed = Arrays.copyOf(hash, 32);
            x25519Seed[0] &= (byte) 0xF8;  // clear bottom 3 bits
            x25519Seed[31] &= (byte) 0x7F; // clear top bit
            x25519Seed[31] |= (byte) 0x40; // set second-to-top bit

            X25519Agreement agreement = new X25519Agreement();
            agreement.init(new X25519PrivateKeyParameters(x25519Seed, 0));
            byte[] secret = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(new X25519PublicKeyParameters(peer, 0), secret, 0);
            Arrays.fill(x25519Seed, (byte) 0);
            return VaultResult.ok(secret);
        } catch (Exception ex) {
            return VaultResult.error(VaultResult.ERR_CRYPTO_FAILURE);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /** BIP-340 tagged hash: SHA-256(SHA-256(tag) || SHA-256(tag) || data) */
    static byte[] taggedHash(String tag, byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] tagHash = md.digest(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.reset();
            md.update(tagHash);
            md.update(tagHash);
            md.update(data);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] bigIntTo32Bytes(BigInteger value) {
        return Slip10KeyDerivator.to32Bytes(value);
    }

    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    private static byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) len += a.length;
        byte[] result = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }
}
