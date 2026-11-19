package club.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static club.dwdc.keyvault.core.KeyVault.*;
import static club.dwdc.keyvault.core.VaultResult.*;
import static club.dwdc.keyvault.core.VaultTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * The 0.6.0 call through {@link Bip32KeyVault#execute}: EXPORT (B5), reserved
 * values, payload lengths and output formats for every implemented
 * {@code (alg, fn, option)}.
 */
class VaultApiTest {

    private static final int ALICE = Bip32KeyDerivator.mangle("alice@atlanta.com");

    private final KeyVault vault = new Bip32KeyVault(MNEMONIC);

    // A path per curve on which every function is allowed by the binding check.
    private static final int[] NOSTR_PATH = ourPath(NOSTR, ALICE, 0, 0);
    private static final int[] PGP_PATH = ourPath(OPENPGP, ALICE, 0, 1);
    private static final int[] SMIME_PATH = ourPath(X509, ALICE, 0, UseField.X509_SMIME);
    private static final int[] SEGWIT_PATH = {84 | H, 0 | H, 0 | H, 0, 0};

    private record Case(String name, Alg alg, int fn, int option, int[] path, byte[] payload) {
    }

    private VaultResult run(Alg alg, int fn, int option, byte[] payload, int... path) {
        return vault.execute(alg, fn, option, payload, path);
    }

    private static byte[] bytes(int length) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (i + 1);
        }
        return b;
    }

    // ── EXPORT (B5) ─────────────────────────────────────────────────────

    @Test
    void exportRefusedForEverySupportedAlgOnEveryKnownPrefix() {
        List<int[]> known = List.of(NOSTR_PATH, ourPath(SSH, ALICE, 0, 0), PGP_PATH, SMIME_PATH,
                ourPath(MLS, ALICE, 0, 0), new int[]{KM_PURPOSE | H, 1 | H, 7 | H, H, 1 | H},
                ourPath(WIREGUARD, ALICE, 0, 0));
        for (Alg alg : new Alg[]{Alg.SECP256K1, Alg.ED25519, Alg.P256}) {
            for (int[] path : known) {
                VaultResult r = run(alg, FN_EXPORT, 0, null, path);
                assertEquals(ERR_UNSUPPORTED_ALGORITHM, r.status(), alg + " " + java.util.Arrays.toString(path));
                assertNull(r.data());
            }
        }
    }

    @Test
    void exportOnNonHardenedPathIsInvalidPath() {
        assertEquals(ERR_INVALID_PATH, run(Alg.SECP256K1, FN_EXPORT, 0, null, SEGWIT_PATH).status());
        assertEquals(ERR_INVALID_PATH, run(Alg.SECP256K1, FN_EXPORT, 0, null,
                KM_PURPOSE | H, 1 | H, 7 | H, H, 1 | H, 5, 0).status());
    }

    @Test
    void exportOfReservedAlgIsUnsupported() {
        for (Alg alg : new Alg[]{Alg.RSA, Alg.ML_DSA, Alg.ML_KEM}) {
            assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(alg, FN_EXPORT, 0, null, PGP_PATH).status());
        }
    }

    // ── Reserved values ─────────────────────────────────────────────────

    @Test
    void reservedAlgs() {
        for (Alg alg : new Alg[]{Alg.RSA, Alg.ML_DSA, Alg.ML_KEM}) {
            for (int fn : new int[]{FN_GET_PUBLIC_KEY, FN_SIGN, FN_KEY_AGREEMENT, FN_DECAPSULATE}) {
                assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(alg, fn, 0, bytes(32), PGP_PATH).status(), alg + " " + fn);
            }
        }
        assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(null, FN_SIGN, 0, bytes(32), PGP_PATH).status());
    }

    @Test
    void reservedAndUnknownFunctions() {
        for (int fn : new int[]{FN_DECAPSULATE, 5, 15, FN_MUSIG2_NONCE, FN_MUSIG2_SIGN, 18, 255, -1}) {
            assertEquals(ERR_UNSUPPORTED_FUNCTION, run(Alg.SECP256K1, fn, 0, bytes(32), NOSTR_PATH).status(), "fn " + fn);
            assertEquals(ERR_UNSUPPORTED_FUNCTION, run(Alg.SECP256K1, fn, 0, bytes(32), SEGWIT_PATH).status(), "fn " + fn);
        }
    }

    @Test
    void reservedAndUnknownOptions() {
        // Reserved: Taproot (SECP256K1 1), Tor blinded (ED25519 1)
        assertEquals(ERR_UNSUPPORTED_ALGORITHM,
                run(Alg.SECP256K1, FN_SIGN, OPT_SECP256K1_TAPROOT, bytes(32), 86 | H, 0 | H, 0 | H, 0, 0).status());
        assertEquals(ERR_UNSUPPORTED_ALGORITHM,
                run(Alg.ED25519, FN_SIGN, OPT_ED25519_TOR_BLINDED, bytes(48), PGP_PATH).status());
        // Unknown
        assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(Alg.SECP256K1, FN_SIGN, 3, bytes(32), NOSTR_PATH).status());
        assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(Alg.SECP256K1, FN_KEY_AGREEMENT, 2, bytes(33), NOSTR_PATH).status());
        assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(Alg.P256, FN_SIGN, 1, bytes(32), SMIME_PATH).status());
        assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(Alg.ED25519, FN_GET_PUBLIC_KEY, 2, null, PGP_PATH).status());
        assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(Alg.P256, FN_SIGN, 256, bytes(32), SMIME_PATH).status());
        assertEquals(ERR_UNSUPPORTED_ALGORITHM, run(Alg.P256, FN_SIGN, -1, bytes(32), SMIME_PATH).status());
    }

    // ── Paths ────────────────────────────────────────────────────────────

    @Test
    void shortPathIsInvalid() {
        assertEquals(ERR_INVALID_PATH, run(Alg.SECP256K1, FN_GET_PUBLIC_KEY, 0, null, 44 | H, NOSTR | H, H, H).status());
        assertEquals(ERR_INVALID_PATH, vault.execute(Alg.SECP256K1, FN_GET_PUBLIC_KEY, 0, null, (int[]) null).status());
    }

    @Test
    void ed25519NonHardenedIsInvalidPath() {
        int[] wireguardSoft = {44 | H, WIREGUARD | H, ALICE | H, H, 0}; // unknown prefix: only the curve refuses
        assertEquals(ERR_INVALID_PATH, run(Alg.ED25519, FN_GET_PUBLIC_KEY, 0, null, wireguardSoft).status());
        assertTrue(run(Alg.P256, FN_GET_PUBLIC_KEY, 0, null, wireguardSoft).isOk());
    }

    @Test
    void bindingRefusalIsInvalidPath() {
        assertEquals(ERR_INVALID_PATH, run(Alg.ED25519, FN_SIGN, 0, bytes(10), NOSTR_PATH).status());
        assertEquals(ERR_INVALID_PATH, run(Alg.P256, FN_KEY_AGREEMENT, 0, bytes(33),
                ourPath(X509, ALICE, 0, UseField.X509_TLS_CLIENT)).status());
    }

    // ── Payload lengths ─────────────────────────────────────────────────

    @Test
    void wrongPayloadLengthForEveryImplementedPair() {
        List<Case> wrong = List.of(
                new Case("k1 gpk payload", Alg.SECP256K1, FN_GET_PUBLIC_KEY, 0, NOSTR_PATH, bytes(1)),
                new Case("ed gpk payload", Alg.ED25519, FN_GET_PUBLIC_KEY, 0, PGP_PATH, bytes(32)),
                new Case("p256 gpk payload", Alg.P256, FN_GET_PUBLIC_KEY, 0, SMIME_PATH, bytes(32)),
                new Case("schnorr 31", Alg.SECP256K1, FN_SIGN, 0, NOSTR_PATH, bytes(31)),
                new Case("schnorr 33", Alg.SECP256K1, FN_SIGN, 0, NOSTR_PATH, bytes(33)),
                new Case("schnorr null", Alg.SECP256K1, FN_SIGN, 0, NOSTR_PATH, null),
                new Case("k1 ecdsa 64", Alg.SECP256K1, FN_SIGN, 2, SEGWIT_PATH, bytes(64)),
                new Case("k1 ecdsa empty", Alg.SECP256K1, FN_SIGN, 2, SEGWIT_PATH, new byte[0]),
                new Case("ed sign null", Alg.ED25519, FN_SIGN, 0, PGP_PATH, null),
                new Case("p256 ecdsa 20", Alg.P256, FN_SIGN, 0, SMIME_PATH, bytes(20)),
                new Case("p256 ecdsa 48", Alg.P256, FN_SIGN, 0, SMIME_PATH, bytes(48)),
                new Case("k1 ecdh 31", Alg.SECP256K1, FN_KEY_AGREEMENT, 0, NOSTR_PATH, bytes(31)),
                new Case("k1 ecdh 65", Alg.SECP256K1, FN_KEY_AGREEMENT, 0, NOSTR_PATH, bytes(65)),
                new Case("k1 ecdh null", Alg.SECP256K1, FN_KEY_AGREEMENT, 0, NOSTR_PATH, null),
                new Case("x25519 33", Alg.ED25519, FN_KEY_AGREEMENT, 0, PGP_PATH, bytes(33)),
                new Case("x25519 empty", Alg.ED25519, FN_KEY_AGREEMENT, 0, PGP_PATH, new byte[0]),
                new Case("p256 ecdh 32", Alg.P256, FN_KEY_AGREEMENT, 0, SMIME_PATH, bytes(32)),
                new Case("p256 ecdh 64", Alg.P256, FN_KEY_AGREEMENT, 0, SMIME_PATH, bytes(64)));
        for (Case c : wrong) {
            assertEquals(ERR_INVALID_PAYLOAD, run(c.alg(), c.fn(), c.option(), c.payload(), c.path()).status(), c.name());
        }
    }

    // ── Output formats ──────────────────────────────────────────────────

    @Test
    void publicKeyFormatsAndChainCodes() {
        VaultResult k1 = run(Alg.SECP256K1, FN_GET_PUBLIC_KEY, 0, null, NOSTR_PATH);
        VaultResult ed = run(Alg.ED25519, FN_GET_PUBLIC_KEY, 0, new byte[0], PGP_PATH);
        VaultResult p256 = run(Alg.P256, FN_GET_PUBLIC_KEY, 0, null, SMIME_PATH);
        assertEquals(33, k1.data().length);
        assertTrue(k1.data()[0] == 2 || k1.data()[0] == 3);
        assertEquals(32, ed.data().length);
        assertEquals(65, p256.data().length);
        assertEquals(4, p256.data()[0]);
        Slip10KeyDerivator kd = Slip10KeyDerivator.fromMnemonic(MNEMONIC, "");
        assertArrayEquals(kd.deriveNode(Alg.SECP256K1, NOSTR_PATH).chainCode(), k1.chainCode());
        assertArrayEquals(kd.deriveNode(Alg.ED25519, PGP_PATH).chainCode(), ed.chainCode());
        assertArrayEquals(kd.deriveNode(Alg.P256, SMIME_PATH).chainCode(), p256.chainCode());
    }

    @Test
    void getPublicKeyTakesTheSchemeOption() {
        // A SegWit key is an ECDSA (option 2) key: GET_PUBLIC_KEY with option 2.
        VaultResult segwit = run(Alg.SECP256K1, FN_GET_PUBLIC_KEY, OPT_SECP256K1_ECDSA, null, SEGWIT_PATH);
        assertTrue(segwit.isOk());
        assertEquals(ERR_INVALID_PATH, run(Alg.SECP256K1, FN_GET_PUBLIC_KEY, 0, null, SEGWIT_PATH).status());
    }

    @Test
    void signatureLengths() {
        assertEquals(64, run(Alg.SECP256K1, FN_SIGN, 0, bytes(32), NOSTR_PATH).data().length);
        assertEquals(65, run(Alg.SECP256K1, FN_SIGN, 2, bytes(32), SEGWIT_PATH).data().length);
        assertEquals(64, run(Alg.ED25519, FN_SIGN, 0, bytes(100), PGP_PATH).data().length);
        assertEquals(64, run(Alg.ED25519, FN_SIGN, 0, new byte[0], PGP_PATH).data().length);
        assertEquals(64, run(Alg.P256, FN_SIGN, 0, bytes(32), SMIME_PATH).data().length);
    }

    @Test
    void onlyGetPublicKeyReturnsAChainCode() {
        assertNull(run(Alg.SECP256K1, FN_SIGN, 0, bytes(32), NOSTR_PATH).chainCode());
        assertNull(run(Alg.ED25519, FN_SIGN, 0, bytes(3), PGP_PATH).chainCode());
    }

    @Test
    void deterministic() {
        assertArrayEquals(run(Alg.P256, FN_SIGN, 0, bytes(32), SMIME_PATH).data(),
                run(Alg.P256, FN_SIGN, 0, bytes(32), SMIME_PATH).data());
        assertArrayEquals(run(Alg.SECP256K1, FN_SIGN, 0, bytes(32), NOSTR_PATH).data(),
                new Bip32KeyVault(MNEMONIC).execute(Alg.SECP256K1, FN_SIGN, 0, bytes(32), NOSTR_PATH).data());
    }
}
