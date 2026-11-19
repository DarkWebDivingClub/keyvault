package club.dwdc.keyvault.core;

import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.ECKey;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.HexFormat;

import static club.dwdc.keyvault.core.KeyVault.*;
import static club.dwdc.keyvault.core.VaultTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Each implemented scheme, checked by an implementation other than the one that
 * produced it: JCA (SunEC) for P-256 ECDSA and ECDH, Ed25519 and X25519; bitcoinj
 * for secp256k1 ECDSA and public key recovery; the BIP-340 verification
 * equation for Schnorr; the NIP-06 test vectors for the Nostr NIP-06 path.
 */
class SchemesTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final int ALICE = Bip32KeyDerivator.mangle("alice@atlanta.com");
    private static final int BOB = Bip32KeyDerivator.mangle("bob@biloxi.com");

    private static final int[] NOSTR_ALICE = ourPath(NOSTR, ALICE, 0, 0);
    private static final int[] NOSTR_BOB = ourPath(NOSTR, BOB, 0, 0);
    private static final int[] PGP_SIGN = ourPath(OPENPGP, ALICE, 0, 1);
    private static final int[] MLS_HPKE = ourPath(MLS, ALICE, 0, 1);
    private static final int[] TLS_CLIENT = ourPath(X509, ALICE, 0, UseField.X509_TLS_CLIENT);
    private static final int[] SMIME = ourPath(X509, ALICE, 0, UseField.X509_SMIME);
    private static final int[] SEGWIT = {84 | H, 0 | H, 0 | H, 0, 7};

    private static final BigInteger N_P256 = CustomNamedCurves.getByName("secp256r1").getN();
    private static final BigInteger N_K1 = CustomNamedCurves.getByName("secp256k1").getN();

    private final KeyVault vault = new Bip32KeyVault(MNEMONIC);

    private byte[] pub(Alg alg, int option, int[] path) {
        VaultResult r = vault.execute(alg, FN_GET_PUBLIC_KEY, option, null, path);
        assertTrue(r.isOk(), "status " + r.status());
        return r.data();
    }

    private byte[] ok(VaultResult r) {
        assertTrue(r.isOk(), "status " + r.status());
        return r.data();
    }

    private static byte[] sha256(String s) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    // ── BIP-340 Schnorr ─────────────────────────────────────────────────

    @Test
    void schnorrVerifiesWithTheBip340Equation() throws Exception {
        byte[] pubCompressed = pub(Alg.SECP256K1, 0, NOSTR_ALICE);
        byte[] px = Arrays.copyOfRange(pubCompressed, 1, 33);
        for (String m : new String[]{"", "nostr event", "another"}) {
            byte[] msg = sha256(m);
            byte[] sig = ok(vault.execute(Alg.SECP256K1, FN_SIGN, 0, msg, NOSTR_ALICE));
            assertTrue(bip340Verify(px, msg, sig), m);
            msg[0] ^= 1;
            assertFalse(bip340Verify(px, msg, sig), "tampered " + m);
        }
    }

    /** BIP-340 Verify(pk, m, sig). */
    static boolean bip340Verify(byte[] px, byte[] msg, byte[] sig) {
        var k1 = CustomNamedCurves.getByName("secp256k1");
        ECCurve curve = k1.getCurve();
        BigInteger p = curve.getField().getCharacteristic();
        BigInteger x = new BigInteger(1, px);
        BigInteger ySq = x.modPow(BigInteger.valueOf(3), p).add(BigInteger.valueOf(7)).mod(p);
        BigInteger y = ySq.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        if (!y.modPow(BigInteger.TWO, p).equals(ySq)) {
            return false;
        }
        if (y.testBit(0)) {
            y = p.subtract(y);
        }
        ECPoint pPoint = curve.createPoint(x, y);
        BigInteger r = new BigInteger(1, Arrays.copyOf(sig, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
        if (r.compareTo(p) >= 0 || s.compareTo(k1.getN()) >= 0) {
            return false;
        }
        byte[] e = Bip32KeyVault.taggedHash("BIP0340/challenge",
                concat(Arrays.copyOf(sig, 32), px, msg));
        BigInteger eInt = new BigInteger(1, e).mod(k1.getN());
        ECPoint bigR = k1.getG().multiply(s).subtract(pPoint.multiply(eInt)).normalize();
        return !bigR.isInfinity() && !bigR.getYCoord().toBigInteger().testBit(0)
                && bigR.getXCoord().toBigInteger().equals(r);
    }

    // ── Ed25519 ─────────────────────────────────────────────────────────

    @Test
    void ed25519VerifiesWithJca() throws Exception {
        byte[] raw = pub(Alg.ED25519, 0, PGP_SIGN);
        PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(
                concat(HEX.parseHex("302a300506032b6570032100"), raw)));
        byte[] msg = "openpgp hashed data".getBytes();
        byte[] sig = ok(vault.execute(Alg.ED25519, FN_SIGN, 0, msg, PGP_SIGN));
        Signature v = Signature.getInstance("Ed25519");
        v.initVerify(key);
        v.update(msg);
        assertTrue(v.verify(sig));
    }

    // ── X25519 ──────────────────────────────────────────────────────────

    @Test
    void x25519EqualsJca() throws Exception {
        // Our X25519 public key is the Montgomery form of the Ed25519 key: u = (1 + y) / (1 - y).
        byte[] edPub = pub(Alg.ED25519, 0, MLS_HPKE);
        BigInteger u = edwardsToMontgomeryU(edPub);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair peer = kpg.generateKeyPair();
        byte[] peerRaw = x25519Raw((java.security.interfaces.XECPublicKey) peer.getPublic());

        byte[] ours = ok(vault.execute(Alg.ED25519, FN_KEY_AGREEMENT, 0, peerRaw, MLS_HPKE));

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(peer.getPrivate());
        ka.doPhase(KeyFactory.getInstance("X25519").generatePublic(
                new XECPublicKeySpec(NamedParameterSpec.X25519, u)), true);
        assertArrayEquals(ka.generateSecret(), ours);
    }

    private static BigInteger edwardsToMontgomeryU(byte[] edPub) {
        BigInteger p = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
        byte[] le = edPub.clone();
        le[31] &= 0x7F;
        byte[] be = reverse(le);
        BigInteger y = new BigInteger(1, be);
        return BigInteger.ONE.add(y).multiply(BigInteger.ONE.subtract(y).mod(p).modInverse(p)).mod(p);
    }

    private static byte[] x25519Raw(java.security.interfaces.XECPublicKey key) {
        byte[] be = Slip10KeyDerivator.to32Bytes(key.getU());
        return reverse(be);
    }

    // ── P-256 ECDSA ─────────────────────────────────────────────────────

    @Test
    void p256EcdsaIsLowSAndVerifiesWithJca() throws Exception {
        ECPublicKey key = p256Public(pub(Alg.P256, 0, TLS_CLIENT));
        for (int i = 0; i < 40; i++) {
            byte[] msg = ("tls certificate verify " + i).getBytes();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(msg);
            byte[] rs = ok(vault.execute(Alg.P256, FN_SIGN, 0, digest, TLS_CLIENT));
            assertEquals(64, rs.length);
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
            assertTrue(s.compareTo(N_P256.shiftRight(1)) <= 0, "low-S, message " + i);
            Signature v = Signature.getInstance("SHA256withECDSA");
            v.initVerify(key);
            v.update(msg);
            assertTrue(v.verify(toDer(rs)), "JCA verify, message " + i);
        }
    }

    // ── secp256k1 ECDSA r‖s‖v ───────────────────────────────────────────

    @Test
    void secp256k1EcdsaIsLowSAndRecoversThePublicKey() throws Exception {
        byte[] expectedPub = pub(Alg.SECP256K1, OPT_SECP256K1_ECDSA, SEGWIT);
        ECKey ref = ECKey.fromPublicOnly(expectedPub);
        boolean sawV0 = false;
        boolean sawV1 = false;
        for (int i = 0; i < 40; i++) {
            byte[] digest = sha256("bitcoin sighash " + i);
            byte[] rsv = ok(vault.execute(Alg.SECP256K1, FN_SIGN, OPT_SECP256K1_ECDSA, digest, SEGWIT));
            assertEquals(65, rsv.length);
            BigInteger r = new BigInteger(1, Arrays.copyOf(rsv, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(rsv, 32, 64));
            int v = rsv[64];
            assertTrue(v == 0 || v == 1, "v " + v);
            sawV0 |= v == 0;
            sawV1 |= v == 1;
            assertTrue(s.compareTo(N_K1.shiftRight(1)) <= 0, "low-S, digest " + i);
            ECKey.ECDSASignature sig = new ECKey.ECDSASignature(r, s);
            assertTrue(ref.verify(Sha256Hash.wrap(digest), sig), "bitcoinj verify, digest " + i);
            ECKey recovered = ECKey.recoverFromSignature(v, sig, Sha256Hash.wrap(digest), true);
            assertNotNull(recovered);
            assertArrayEquals(expectedPub, recovered.getPubKey(), "recovered key, digest " + i);
        }
        assertTrue(sawV0 && sawV1, "both recovery ids seen in 40 signatures");
    }

    // ── P-256 ECDH ──────────────────────────────────────────────────────

    @Test
    void p256EcdhEqualsJca() throws Exception {
        byte[] ourPub = pub(Alg.P256, 0, SMIME);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair peer = kpg.generateKeyPair();
        ECPublicKey peerPub = (ECPublicKey) peer.getPublic();
        byte[] uncompressed = concat(new byte[]{4},
                Slip10KeyDerivator.to32Bytes(peerPub.getW().getAffineX()),
                Slip10KeyDerivator.to32Bytes(peerPub.getW().getAffineY()));
        byte[] compressed = CustomNamedCurves.getByName("secp256r1").getCurve()
                .decodePoint(uncompressed).getEncoded(true);

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(peer.getPrivate());
        ka.doPhase(p256Public(ourPub), true);
        byte[] expected = ka.generateSecret();

        assertArrayEquals(expected, ok(vault.execute(Alg.P256, FN_KEY_AGREEMENT, 0, uncompressed, SMIME)));
        assertArrayEquals(expected, ok(vault.execute(Alg.P256, FN_KEY_AGREEMENT, 0, compressed, SMIME)));
        int[] smimeEncrypt = ourPath(X509, ALICE, 0, UseField.X509_SMIME_ENCRYPT);
        assertTrue(vault.execute(Alg.P256, FN_KEY_AGREEMENT, 0, compressed, smimeEncrypt).isOk());
    }

    @Test
    void p256EcdhInvalidPeerPointIsCryptoFailure() {
        byte[] offCurve = new byte[65];
        offCurve[0] = 4;
        offCurve[32] = 1;
        offCurve[64] = 1;
        assertEquals(VaultResult.ERR_CRYPTO_FAILURE,
                vault.execute(Alg.P256, FN_KEY_AGREEMENT, 0, offCurve, SMIME).status());
        byte[] badPrefix = new byte[33];
        badPrefix[0] = 5;
        assertEquals(VaultResult.ERR_CRYPTO_FAILURE,
                vault.execute(Alg.P256, FN_KEY_AGREEMENT, 0, badPrefix, SMIME).status());
    }

    // ── secp256k1 ECDH ──────────────────────────────────────────────────

    @Test
    void secp256k1EcdhIsSymmetricAndAcceptsXOnly() {
        byte[] alicePub = pub(Alg.SECP256K1, 0, NOSTR_ALICE);
        byte[] bobPub = pub(Alg.SECP256K1, 0, NOSTR_BOB);
        byte[] ab = ok(vault.execute(Alg.SECP256K1, FN_KEY_AGREEMENT, 0, bobPub, NOSTR_ALICE));
        byte[] ba = ok(vault.execute(Alg.SECP256K1, FN_KEY_AGREEMENT, 0, alicePub, NOSTR_BOB));
        assertArrayEquals(ab, ba);
        // x-only (NIP-44): the x coordinate of the shared point does not depend on the peer's y
        byte[] abXOnly = ok(vault.execute(Alg.SECP256K1, FN_KEY_AGREEMENT, 0,
                Arrays.copyOfRange(bobPub, 1, 33), NOSTR_ALICE));
        assertArrayEquals(ab, abXOnly);
    }

    // ── NIP-06 ──────────────────────────────────────────────────────────

    @Test
    void nip06TestVectors() {
        assertNip06("leader monkey parrot ring guide accident before fence cannon height naive bean",
                "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917");
        assertNip06("what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud "
                        + "rude strong choose busy staff weather area salt hollow arm fade",
                "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573");
    }

    private static void assertNip06(String mnemonic, String xOnlyHex) {
        KeyVault v = new Bip32KeyVault(mnemonic);
        int[] nip06 = {44 | H, NOSTR | H, 0 | H, 0, 0};
        VaultResult r = v.execute(Alg.SECP256K1, FN_GET_PUBLIC_KEY, 0, null, nip06);
        assertTrue(r.isOk(), "status " + r.status());
        assertEquals(xOnlyHex, HEX.formatHex(Arrays.copyOfRange(r.data(), 1, 33)));
        assertTrue(v.execute(Alg.SECP256K1, FN_SIGN, 0, new byte[32], nip06).isOk());
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static ECPublicKey p256Public(byte[] uncompressed) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        java.security.spec.ECPoint w = new java.security.spec.ECPoint(
                new BigInteger(1, Arrays.copyOfRange(uncompressed, 1, 33)),
                new BigInteger(1, Arrays.copyOfRange(uncompressed, 33, 65)));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, spec));
    }

    /** Raw r‖s → DER SEQUENCE { INTEGER r, INTEGER s }. */
    static byte[] toDer(byte[] rs) {
        byte[] r = new BigInteger(1, Arrays.copyOf(rs, 32)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64)).toByteArray();
        byte[] body = concat(new byte[]{2, (byte) r.length}, r, new byte[]{2, (byte) s.length}, s);
        return concat(new byte[]{0x30, (byte) body.length}, body);
    }

    private static byte[] reverse(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length - 1 - i];
        }
        return out;
    }

    static byte[] concat(byte[]... parts) {
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
