package club.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static club.dwdc.keyvault.core.KeyVault.*;
import static club.dwdc.keyvault.core.VaultTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * The binding check (B6): each row of the table in {@code api-0.6.0.md} section 6
 * (plus the X.509 row of mission 48.2) accepts exactly its {@code (alg, option)}
 * pairs and functions; everything else on a known prefix is refused, and
 * unknown prefixes pass.
 */
class BindingTest {

    private static final int ALICE = Bip32KeyDerivator.mangle("alice@atlanta.com");
    private static final Alg[] CURVES = {Alg.SECP256K1, Alg.ED25519, Alg.P256};
    private static final int[] OPTIONS = {0, 1, 2, 3};
    private static final int[] FNS = {FN_GET_PUBLIC_KEY, FN_SIGN, FN_KEY_AGREEMENT};

    private static final Set<Integer> SIGN_ONLY = Set.of(FN_GET_PUBLIC_KEY, FN_SIGN);
    private static final Set<Integer> ALL3 = Set.of(FN_GET_PUBLIC_KEY, FN_SIGN, FN_KEY_AGREEMENT);
    private static final Set<Integer> AGREE_ONLY = Set.of(FN_GET_PUBLIC_KEY, FN_KEY_AGREEMENT);

    private record Pair(Alg alg, int option) {
    }

    /** Every (alg, option, fn) on {@code path}: allowed exactly when the pair and fn are listed. */
    private static void assertRow(String name, int[] path, Set<Pair> pairs, Set<Integer> fns) {
        for (Alg alg : CURVES) {
            for (int option : OPTIONS) {
                for (int fn : FNS) {
                    boolean allowed = pairs.contains(new Pair(alg, option)) && fns.contains(fn);
                    int expected = allowed ? VaultResult.OK : VaultResult.ERR_INVALID_PATH;
                    assertEquals(expected, Binding.check(alg, fn, option, path),
                            name + " " + alg + " option " + option + " fn " + fn);
                }
            }
        }
    }

    @Test
    void nostr() {
        assertRow("Nostr", ourPath(NOSTR, ALICE, 0, 0), Set.of(new Pair(Alg.SECP256K1, 0)), ALL3);
    }

    @Test
    void ssh() {
        assertRow("SSH", ourPath(SSH, ALICE, 0, 0),
                Set.of(new Pair(Alg.ED25519, 0), new Pair(Alg.P256, 0)), SIGN_ONLY);
    }

    @Test
    void openpgp() {
        for (int role = 0; role <= 2; role++) {
            assertRow("OpenPGP role " + role, ourPath(OPENPGP, ALICE, 0, role),
                    Set.of(new Pair(Alg.ED25519, 0)), ALL3);
        }
    }

    @Test
    void mls() {
        for (int role = 0; role <= 1; role++) {
            assertRow("MLS role " + role, ourPath(MLS, ALICE, 0, role),
                    Set.of(new Pair(Alg.ED25519, 0), new Pair(Alg.P256, 0)), ALL3);
        }
    }

    @Test
    void x509PerRole() {
        Set<Pair> p256 = Set.of(new Pair(Alg.P256, 0));
        assertRow("X.509 ca", ourPath(X509, ALICE, 0, UseField.X509_CA), p256, SIGN_ONLY);
        assertRow("X.509 tls-server", ourPath(X509, ALICE, 0, UseField.X509_TLS_SERVER), p256, SIGN_ONLY);
        assertRow("X.509 tls-client", ourPath(X509, ALICE, 0, UseField.X509_TLS_CLIENT), p256, SIGN_ONLY);
        assertRow("X.509 code-signing", ourPath(X509, ALICE, 0, UseField.X509_CODE_SIGNING), p256, SIGN_ONLY);
        assertRow("X.509 smime", ourPath(X509, ALICE, 0, UseField.X509_SMIME), p256, ALL3);
        assertRow("X.509 smime-encrypt", ourPath(X509, ALICE, 0, UseField.X509_SMIME_ENCRYPT), p256, AGREE_ONLY);
        for (int role : new int[]{6, 7, 128, 255}) {
            assertRow("X.509 role " + role, ourPath(X509, ALICE, 0, role), p256, Set.of());
        }
    }

    @Test
    void realms() {
        int[] connector = {KM_PURPOSE | H, 1 | H, 7 | H, H, 12345 | H};
        int[] channel = {KM_PURPOSE | H, 1 | H, 7 | H, H, 12345 | H, Bip32KeyDerivator.mangle("ssh"), 3};
        assertRow("realm connector", connector, Set.of(new Pair(Alg.SECP256K1, 0)), ALL3);
        assertRow("realm service channel", channel, Set.of(new Pair(Alg.SECP256K1, 0)), ALL3);
    }

    @Test
    void bitcoinStandardTrees() {
        assertRow("Taproot", new int[]{86 | H, 0 | H, 0 | H, 0, 0},
                Set.of(new Pair(Alg.SECP256K1, OPT_SECP256K1_TAPROOT)), SIGN_ONLY);
        assertRow("SegWit", new int[]{84 | H, 0 | H, 0 | H, 0, 0},
                Set.of(new Pair(Alg.SECP256K1, OPT_SECP256K1_ECDSA)), SIGN_ONLY);
    }

    @Test
    void unknownPrefixesPass() {
        int[][] unknown = {
                ourPath(WIREGUARD, ALICE, 0, 0),
                {44 | H, 0 | H, 0 | H, 0, 0},           // BIP-44 Bitcoin
                {49 | H, 0 | H, 0 | H, 0, 0},           // BIP-49
                {44 | H, 60 | H, 0 | H, 0, 0},          // Ethereum
                {KM_PURPOSE | H, 2 | H, 7 | H, H, H},   // realm scheme 2 (not defined)
        };
        for (int[] path : unknown) {
            for (Alg alg : CURVES) {
                for (int option : OPTIONS) {
                    for (int fn : FNS) {
                        assertEquals(VaultResult.OK, Binding.check(alg, fn, option, path));
                    }
                }
            }
        }
    }

    // ── use' rules on our trees ──────────────────────────────────────────

    @Test
    void variantMustEqualOption() {
        int[] variant1 = ourPath(SSH, ALICE, 1, 0);
        assertEquals(VaultResult.ERR_INVALID_PATH, Binding.check(Alg.ED25519, FN_SIGN, 0, variant1));
        int[] x509Variant1 = ourPath(X509, ALICE, 1, UseField.X509_TLS_CLIENT); // the 0.5.x "variant = curve"
        assertEquals(VaultResult.ERR_INVALID_PATH, Binding.check(Alg.P256, FN_SIGN, 0, x509Variant1));
    }

    @Test
    void reservedBitsRefused() {
        // The 0.5.x paths: algorithm in bits 30-16.
        int[] legacySsh = {44 | H, SSH | H, ALICE | H, 0x00010000 | H, H};
        int[] legacyX509 = {44 | H, X509 | H, ALICE | H, 0x00030102 | H, H};
        int[] legacyPgpSigning = {44 | H, OPENPGP | H, ALICE | H, 0x00010001 | H, H};
        assertEquals(VaultResult.ERR_INVALID_PATH, Binding.check(Alg.ED25519, FN_SIGN, 0, legacySsh));
        assertEquals(VaultResult.ERR_INVALID_PATH, Binding.check(Alg.P256, FN_SIGN, 0, legacyX509));
        assertEquals(VaultResult.ERR_INVALID_PATH, Binding.check(Alg.ED25519, FN_SIGN, 0, legacyPgpSigning));
        // Nostr and realm paths had algorithm 0, so their 0.5.x values stay valid.
        assertEquals(VaultResult.OK, Binding.check(Alg.SECP256K1, FN_SIGN, 0, new int[]{44 | H, NOSTR | H, ALICE | H, H, H}));
    }

    @Test
    void ourTreesMustBeHardened() {
        int[] softLeaf = {44 | H, SSH | H, ALICE | H, H, 0};
        int[] softIdentity = {44 | H, MLS | H, ALICE, H, H};
        assertEquals(VaultResult.ERR_INVALID_PATH, Binding.check(Alg.P256, FN_SIGN, 0, softLeaf));
        assertEquals(VaultResult.ERR_INVALID_PATH, Binding.check(Alg.P256, FN_SIGN, 0, softIdentity));
    }

    @Test
    void nip06ShapeAccepted() {
        int[] nip06 = {44 | H, NOSTR | H, 0 | H, 0, 0};
        assertRow("NIP-06", nip06, Set.of(new Pair(Alg.SECP256K1, 0)), ALL3);
        int[] nip06Account3 = {44 | H, NOSTR | H, 3 | H, 0, 0};
        assertEquals(VaultResult.OK, Binding.check(Alg.SECP256K1, FN_SIGN, 0, nip06Account3));
        // change level 1 and mixed hardening are not NIP-06
        assertEquals(VaultResult.ERR_INVALID_PATH,
                Binding.check(Alg.SECP256K1, FN_SIGN, 0, new int[]{44 | H, NOSTR | H, 0 | H, 1, 0}));
        assertEquals(VaultResult.ERR_INVALID_PATH,
                Binding.check(Alg.SECP256K1, FN_SIGN, 0, new int[]{44 | H, NOSTR | H, 0 | H, H, 0}));
    }
}
