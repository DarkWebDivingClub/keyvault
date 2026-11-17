package club.dwdc.keyvault.core;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ECDSA (alg 3) in the vault — mission 37.1.1.
 * One test per DoD item. See keymaster-wks/doc/key-derivation.md, "ECDSA — alg 3".
 */
class EcdsaTest {

    private static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private static final int H = 0x80000000;
    private static final int PURPOSE = 44 | H;
    private static final int X509 = Protocol.X509.coinType() | H;
    private static final int ALICE = Bip32KeyDerivator.mangle("alice@atlanta.com") | H;

    // ECDSA, X.509 role 2 = TLS client. Variant 1 = P-256, variant 0 = secp256k1.
    private static final int P256_ALG = new AlgField(AlgField.ALG_ECDSA, 1, 2).toIndex() | H; // 196866
    private static final int K1_ALG = new AlgField(AlgField.ALG_ECDSA, 0, 2).toIndex() | H;   // 196610
    private static final int CFG = new ConfigField(0, 0).toIndex() | H;

    // m/44'/1240'/1955269225'/196866'/0' — Alice's TLS-client key (KeyMaster, 37.1.2)
    private static final int[] PATH = {PURPOSE, X509, ALICE, P256_ALG, CFG};
    private static final int[] K1_PATH = {PURPOSE, X509, ALICE, K1_ALG, CFG};

    // Pinned after openssl and BouncyCastle verification passed for this key.
    private static final String GOLDEN_P256_PUB =
            "04b99b60d501f8c4410839779fbea199d87b83dd675ffba53223529adfd0f05ac8" +
            "3c199adda4b7b7aaad50afd3ed4b230361e6ce56ea78790707cb7d84a81a2a81";
    private static final String GOLDEN_CHAIN_CODE =
            "e387b481080f4915aeabcf832222ad93b0a381a218593ae7e8a9e46a9d5dd8cf";

    // P-256 constants, written out so the test does not just trust BouncyCastle.
    private static final BigInteger P256_N = new BigInteger(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    private static final BigInteger P256_P = new BigInteger(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    private static final String P256_G_UNCOMPRESSED =
            "04" +
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    // DER prefix of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1, 66-byte BIT STRING)
    private static final String P256_SPKI_PREFIX =
            "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    private static final ECDomainParameters P256 = domain("secp256r1");
    private static final ECDomainParameters SECP256K1 = domain("secp256k1");

    private final KeyVault vault = new Bip32KeyVault(MNEMONIC);

    // ── 1. P-256 key at a pinned path ────────────────────────────────────

    @Test
    void p256KeyAtPinnedPath() {
        VaultResult pub = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, PATH);
        assertTrue(pub.isOk());
        assertEquals(GOLDEN_P256_PUB, hex(pub.data()));

        byte[] expectedChain = new Bip32KeyDerivator(MNEMONIC, "").deriveKey(PATH).getChainCode();
        assertArrayEquals(expectedChain, pub.chainCode());
        assertEquals(GOLDEN_CHAIN_CODE, hex(pub.chainCode()));
    }

    // ── 2. Same seed and path → same key ─────────────────────────────────

    @Test
    void sameSeedAndPathSameKey() {
        VaultResult a = new Bip32KeyVault(MNEMONIC).execute(KeyVault.FN_GET_PUBLIC_KEY, null, PATH);
        VaultResult b = new Bip32KeyVault(MNEMONIC).execute(KeyVault.FN_GET_PUBLIC_KEY, null, PATH);
        assertTrue(a.isOk());
        assertTrue(b.isOk());
        assertArrayEquals(a.data(), b.data());
        assertArrayEquals(a.chainCode(), b.chainCode());
    }

    // ── 3. sign() verifies with openssl ──────────────────────────────────

    @Test
    void signatureVerifiesWithOpenssl() throws Exception {
        assumeTrue(opensslAvailable(),
                "openssl not found on PATH; skipping external ECDSA verification");

        byte[] pub = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, PATH).data();
        byte[] digest = sha256("keyvault ecdsa openssl check");
        VaultResult sig = vault.execute(KeyVault.FN_SIGN, digest, PATH);
        assertTrue(sig.isOk());

        Path dir = Path.of("target", "ecdsa-openssl");
        Files.createDirectories(dir);
        Path pubDer = dir.resolve("pub.der");
        Path digestBin = dir.resolve("digest.bin");
        Path sigDer = dir.resolve("sig.der");
        Files.write(pubDer, concat(unhex(P256_SPKI_PREFIX), pub));
        Files.write(digestBin, digest);
        Files.write(sigDer, toDer(sig.data()));

        OpensslResult ok = opensslVerify(pubDer, digestBin, sigDer);
        assertEquals(0, ok.exitCode, ok.output);
        assertTrue(ok.output.contains("Signature Verified Successfully"), ok.output);

        // Negative control: one flipped bit must make openssl reject it.
        byte[] tampered = digest.clone();
        tampered[0] ^= 0x01;
        Files.write(digestBin, tampered);
        OpensslResult bad = opensslVerify(pubDer, digestBin, sigDer);
        assertNotEquals(0, bad.exitCode, bad.output);

        Files.write(digestBin, digest); // leave the good digest for manual re-checks
    }

    // ── 4. sign() returns 64-byte raw r||s, not DER ──────────────────────

    @Test
    void signReturns64ByteRawRS() {
        byte[] pub = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, PATH).data();
        byte[] digest = sha256("raw r||s");
        VaultResult sig = vault.execute(KeyVault.FN_SIGN, digest, PATH);

        assertTrue(sig.isOk());
        assertEquals(64, sig.data().length);
        assertNull(sig.chainCode());
        assertTrue(bcVerify(P256, pub, digest, sig.data()), "first 32 bytes = r, last 32 = s");

        // Padding helper: BigInteger with the high bit set has a 33-byte toByteArray()
        BigInteger high = new BigInteger("80" + "00".repeat(31), 16);
        assertEquals(33, high.toByteArray().length);
        byte[] highBytes = Bip32KeyVault.bigIntTo32Bytes(high);
        assertEquals(32, highBytes.length);
        assertEquals((byte) 0x80, highBytes[0]);

        // ...and a short value is left-padded
        byte[] oneBytes = Bip32KeyVault.bigIntTo32Bytes(BigInteger.ONE);
        assertEquals(32, oneBytes.length);
        assertEquals(1, oneBytes[31]);
        assertArrayEquals(new byte[31], Arrays.copyOf(oneBytes, 31));
    }

    // ── 5. Crafted leaf just above n → documented scalar ─────────────────

    @Test
    void craftedLeafAboveN() {
        assertEquals(P256_N, P256.getN(), "hard-coded n must match BouncyCastle");
        assertEquals(P256_G_UNCOMPRESSED, hex(P256.getG().getEncoded(false)));

        byte[] leaf = unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"); // n + 1
        assertEquals(BigInteger.ONE, Bip32KeyVault.leafToScalar(leaf, P256_N));

        // d = 1, so the public key is the generator G
        VaultResult pub = Bip32KeyVault.ecdsaPublicKey(leaf, 1, new byte[32]);
        assertTrue(pub.isOk());
        assertEquals(P256_G_UNCOMPRESSED, hex(pub.data()));
    }

    // ── 6. Reducing mod p instead of n gives a different value ───────────

    @Test
    void reducingModPDiffers() {
        byte[] leaf = unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"); // n + 1
        BigInteger modP = Bip32KeyVault.leafToScalar(leaf, P256_P);
        assertEquals(P256_N.add(BigInteger.ONE), modP, "n + 1 < p, so mod p leaves it unchanged");
        assertNotEquals(Bip32KeyVault.leafToScalar(leaf, P256_N), modP);
    }

    // ── 7. variant selects the curve ─────────────────────────────────────

    @Test
    void variantSelectsCurve() {
        byte[] p256Pub = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, PATH).data();
        byte[] k1Pub = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, K1_PATH).data();

        assertEquals(65, p256Pub.length);
        assertEquals(65, k1Pub.length);
        assertFalse(Arrays.equals(p256Pub, k1Pub));

        // Each key is a point on its own curve, and not on the other one
        assertDoesNotThrow(() -> P256.getCurve().decodePoint(p256Pub));
        assertThrows(IllegalArgumentException.class, () -> SECP256K1.getCurve().decodePoint(p256Pub));
        assertDoesNotThrow(() -> SECP256K1.getCurve().decodePoint(k1Pub));
        assertThrows(IllegalArgumentException.class, () -> P256.getCurve().decodePoint(k1Pub));

        // Variant 0 signs too, on secp256k1
        byte[] digest = sha256("variant 0");
        VaultResult sig = vault.execute(KeyVault.FN_SIGN, digest, K1_PATH);
        assertTrue(sig.isOk());
        assertTrue(bcVerify(SECP256K1, k1Pub, digest, sig.data()));
    }

    // ── 8. Zero scalar rejected ──────────────────────────────────────────

    @Test
    void zeroScalarRejected() {
        byte[] nBytes = unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        assertNull(Bip32KeyVault.leafToScalar(nBytes, P256_N));
        assertNull(Bip32KeyVault.leafToScalar(new byte[32], P256_N));

        assertEquals(VaultResult.ERR_CRYPTO_FAILURE,
                Bip32KeyVault.ecdsaPublicKey(nBytes, 1, new byte[32]).status());
        assertEquals(VaultResult.ERR_CRYPTO_FAILURE,
                Bip32KeyVault.ecdsaSign(nBytes, 1, new byte[32]).status());
    }

    // ── 9. Digest length != 32 rejected ──────────────────────────────────

    @Test
    void digestNot32Rejected() {
        for (int len : new int[] {31, 33, 64}) {
            assertEquals(VaultResult.ERR_INVALID_PAYLOAD,
                    vault.execute(KeyVault.FN_SIGN, new byte[len], PATH).status(), "length " + len);
        }
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD,
                vault.execute(KeyVault.FN_SIGN, null, PATH).status());
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD,
                vault.execute(KeyVault.FN_SIGN, new byte[0], PATH).status());

        // Same code as the Schnorr arm
        int schnorr = new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
        int nostr = Protocol.NOSTR.coinType() | H;
        assertEquals(VaultResult.ERR_INVALID_PAYLOAD,
                vault.execute(KeyVault.FN_SIGN, new byte[31], PURPOSE, nostr, ALICE, schnorr, CFG).status());
    }

    // ── 10. Variant 4 (and other unsupported variants) rejected ──────────

    @Test
    void unsupportedVariantsRejected() {
        for (int variant : new int[] {4, 2, 255}) {
            int alg = new AlgField(AlgField.ALG_ECDSA, variant, 2).toIndex() | H;
            int[] path = {PURPOSE, X509, ALICE, alg, CFG};
            assertEquals(VaultResult.ERR_UNSUPPORTED_ALGORITHM,
                    vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path).status(), "variant " + variant);
            assertEquals(VaultResult.ERR_UNSUPPORTED_ALGORITHM,
                    vault.execute(KeyVault.FN_SIGN, new byte[32], path).status(), "variant " + variant);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static ECDomainParameters domain(String name) {
        var p = CustomNamedCurves.getByName(name);
        return new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
    }

    /** BouncyCastle ECDSA verify of a raw 64-byte r||s signature. */
    private static boolean bcVerify(ECDomainParameters curve, byte[] pub, byte[] digest, byte[] rs) {
        ECPoint q = curve.getCurve().decodePoint(pub);
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(q, curve));
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        return verifier.verifySignature(digest, r, s);
    }

    /** Raw r||s → DER SEQUENCE { INTEGER r, INTEGER s }, which openssl expects. */
    private static byte[] toDer(byte[] rs) throws IOException {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        return new DERSequence(new ASN1Integer[] {new ASN1Integer(r), new ASN1Integer(s)}).getEncoded();
    }

    private static boolean opensslAvailable() {
        try {
            Process p = new ProcessBuilder("openssl", "version").redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    private record OpensslResult(int exitCode, String output) {}

    private static OpensslResult opensslVerify(Path pub, Path digest, Path sig) throws Exception {
        Process p = new ProcessBuilder("openssl", "pkeyutl", "-verify",
                "-pubin", "-inkey", pub.toString(), "-keyform", "DER",
                "-in", digest.toString(), "-sigfile", sig.toString())
                .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(p.waitFor(30, TimeUnit.SECONDS), "openssl timed out");
        return new OpensslResult(p.exitValue(), out);
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] unhex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
