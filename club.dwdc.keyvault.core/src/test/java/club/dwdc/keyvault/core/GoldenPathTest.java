package club.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static club.dwdc.keyvault.core.VaultTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Pinned keys for the "all abandon" mnemonic, API 0.6.0 (missions 48.1 and 48.2).
 *
 * <p>The Ed25519 and P-256 values were computed independently of this code by
 * {@code tools/slip10_ref.py} (hashlib/hmac SLIP-10, public keys from Python
 * {@code cryptography}), 2026-11-19: 48.1 step 6, the cross-check.
 *
 * <p>The secp256k1 values are the 0.5.x values, unchanged: SLIP-10 under
 * {@code "Bitcoin seed"} is BIP-32. If one of those changes, every Nostr npub,
 * realm xpub and transport key changes with it.
 */
class GoldenPathTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final int ALICE = Bip32KeyDerivator.mangle("alice@atlanta.com");

    private final Slip10KeyDerivator kd = Slip10KeyDerivator.fromMnemonic(MNEMONIC, "");
    private final KeyVault vault = new Bip32KeyVault(MNEMONIC);

    private String key(Alg alg, int... path) {
        return HEX.formatHex(kd.derive(alg, path));
    }

    private String pub(Alg alg, int... path) {
        VaultResult r = vault.execute(alg, KeyVault.FN_GET_PUBLIC_KEY, 0, null, path);
        assertTrue(r.isOk(), "status " + r.status());
        return HEX.formatHex(r.data());
    }

    // ── secp256k1: unchanged from 0.5.x ─────────────────────────────────

    /** m/44'/1237'/0'/0'/0' — Nostr default identity. */
    @Test
    void nostrDefault() {
        int[] path = {44 | H, NOSTR | H, H, H, H};
        assertEquals("4f2d32ade6250539bb989a7cffd1d5ec882d16864f502632b6d4f087591f0ee1", key(Alg.SECP256K1, path));
        assertEquals("02c62c24ff183cdbb83d8ebf0e37a634c8c6d6e11cfb5256ac8c129e2f8f899e80", pub(Alg.SECP256K1, path));
    }

    /** m/44'/0'/0'/0'/0' — BIP-32 reference path (no binding row). */
    @Test
    void bitcoinDefault() {
        assertEquals("9138aa040b219a14ef56d98c7c587b9bb02a02015c870cf9c2dbfc333a295be0",
                key(Alg.SECP256K1, 44 | H, 0 | H, 0 | H, 0 | H, 0 | H));
    }

    /** m/44'/0'/0'/1'/0' — BIP-32 reference path. */
    @Test
    void bitcoinChange() {
        assertEquals("24ed19a7ca741bd91b3b16b2460565bf24b08820794b56e6f9bb6367a8806fee",
                key(Alg.SECP256K1, 44 | H, 0 | H, 0 | H, 1 | H, 0 | H));
    }

    // ── Ed25519: new in 0.6.0 (SLIP-10 "ed25519 seed") ──────────────────

    /**
     * m/44'/1238'/0'/0'/0' — SSH default, role 0.
     * 0.5.x: path[3] was 0x00010000 (ALG_ED25519) and the key was the BIP-32
     * secp256k1 leaf fa86e58223df8bd86ec4492877b0b5d9320bbf815707d2c8509d82ee16a2ba79.
     */
    @Test
    void sshDefault() {
        int[] path = ourPath(SSH, 0, 0, 0);
        assertEquals("2fe7c48331ac7285d35c80c4abad4cfb7a2c08ae0ade7f9a2cd2f3b6f57a5f7f", key(Alg.ED25519, path));
        assertEquals("e03d1d391def9a1da4a04d31dab798b551d58bd0e2fe885c0afa8f74f853462c", pub(Alg.ED25519, path));
    }

    /**
     * m/44'/1238'/mangle("alice@atlanta.com")'/0'/0' — SSH, named identity.
     * 0.5.x (path[3] 0x00010000): 11137dbe0698580e6a9f6d1efe50a8ca0ec547ba08d2b3d037964d2e6c2e5911.
     */
    @Test
    void sshAlice() {
        int[] path = ourPath(SSH, ALICE, 0, 0);
        assertEquals("adca5daa39ba09e4278c01c7a68a19c746f7333fd8fb3f665fb3ee145a1eb340", key(Alg.ED25519, path));
        assertEquals("2b8c399b778b33224e5077bbdf47965547816e5fe0c4d34aa776830a74bc5ab3", pub(Alg.ED25519, path));
    }

    /** m/44'/1239'/alice'/0'/0' and /1'/0' — OpenPGP certification and signing roles. */
    @Test
    void openpgpAlice() {
        assertEquals("ed8ed5a4c6208544a5973a169b69ed9f7b0c0c119fdde109640056b3e4118970",
                pub(Alg.ED25519, ourPath(OPENPGP, ALICE, 0, 0)));
        assertEquals("75d03b1e63bbf41409d996516bfe632d61bd7df90bba997f64c5cb9513ca0a96",
                pub(Alg.ED25519, ourPath(OPENPGP, ALICE, 0, 1)));
    }

    /** m/44'/1242'/alice'/0'/0' — MLS signing role. */
    @Test
    void mlsAliceSigning() {
        assertEquals("c6921ad0a88c81de4edc43ea654451c6b3a8239e501e1f04f46e707af0261163",
                pub(Alg.ED25519, ourPath(MLS, ALICE, 0, 0)));
    }

    // ── P-256: new in 0.6.0 (SLIP-10 "Nist256p1 seed") ──────────────────

    /**
     * m/44'/1240'/alice'/2'/0' — X.509 tls-client.
     * 0.5.x: path[3] 0x30102, key = BIP-32 secp256k1 leaf mod n.
     */
    @Test
    void x509AliceTlsClient() {
        int[] path = ourPath(X509, ALICE, 0, UseField.X509_TLS_CLIENT);
        assertEquals("09642144a5976e197dda2a27934db36d1e0f916b86cdbeb906a02a4854647b08", key(Alg.P256, path));
        assertEquals("04c668dd0ec2699cd16e97b2a8a0dc6631b078309c1263757621234186e93db4d7"
                + "70dbaa62e4036255300087d5c43e872cd6fb242a9f87a80786643da9067a53f6", pub(Alg.P256, path));
    }

    // ── Isolation ───────────────────────────────────────────────────────

    /** The same path under different roots gives unrelated keys. */
    @Test
    void samePathDifferentRootsDiffer() {
        int[] path = ourPath(SSH, ALICE, 0, 0);
        assertNotEquals(key(Alg.ED25519, path), key(Alg.SECP256K1, path));
        assertNotEquals(key(Alg.ED25519, path), key(Alg.P256, path));
        assertNotEquals(key(Alg.P256, path), key(Alg.SECP256K1, path));
    }

    /** Roles under one identity give different keys. */
    @Test
    void rolesDiffer() {
        assertNotEquals(key(Alg.ED25519, ourPath(OPENPGP, ALICE, 0, 0)),
                key(Alg.ED25519, ourPath(OPENPGP, ALICE, 0, 1)));
    }
}
