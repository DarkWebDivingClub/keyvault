package club.dwdc.keyvault.core;

import java.util.List;
import java.util.Set;

/**
 * The binding check (API 0.6.0, B6, section 6): on known path prefixes the
 * vault accepts only the listed {@code (alg, option)} pairs and functions.
 * Unknown prefixes are the caller's choice.
 *
 * <table>
 *   <caption>Binding table</caption>
 *   <tr><th>Prefix</th><th>(alg, option)</th><th>Functions</th></tr>
 *   <tr><td>m/44'/1237' Nostr</td><td>(SECP256K1, 0)</td><td>GET_PUBLIC_KEY, SIGN, KEY_AGREEMENT</td></tr>
 *   <tr><td>m/44'/1238' SSH</td><td>(ED25519, 0), (P256, 0)</td><td>GET_PUBLIC_KEY, SIGN</td></tr>
 *   <tr><td>m/44'/1239' OpenPGP</td><td>(ED25519, 0)</td><td>GET_PUBLIC_KEY, SIGN, KEY_AGREEMENT</td></tr>
 *   <tr><td>m/44'/1240' X.509</td><td>(P256, 0)</td><td>per role, see below</td></tr>
 *   <tr><td>m/44'/1242' MLS</td><td>(ED25519, 0), (P256, 0)</td><td>GET_PUBLIC_KEY, SIGN, KEY_AGREEMENT</td></tr>
 *   <tr><td>m/mangle("keymaster")'/1' realms</td><td>(SECP256K1, 0)</td><td>GET_PUBLIC_KEY, SIGN, KEY_AGREEMENT</td></tr>
 *   <tr><td>m/86'/0' Taproot</td><td>(SECP256K1, 1)</td><td>GET_PUBLIC_KEY, SIGN</td></tr>
 *   <tr><td>m/84'/0' SegWit</td><td>(SECP256K1, 2)</td><td>GET_PUBLIC_KEY, SIGN</td></tr>
 * </table>
 *
 * <p>X.509 roles ({@code path[3]} bits 7–0): 0–3 ({@code ca}, {@code tls-server},
 * {@code tls-client}, {@code code-signing}) GET_PUBLIC_KEY and SIGN; 4
 * {@code smime} also KEY_AGREEMENT; 5 {@code smime-encrypt} GET_PUBLIC_KEY and
 * KEY_AGREEMENT; 6 and up refused until defined.
 *
 * <p>On our own trees (the {@code 44'} protocol trees and the realm tree) the
 * first five levels must be hardened, {@code path[3]} bits 30–16 must be 0, and
 * its variant must equal {@code option}. The Nostr tree also accepts the
 * NIP-06 shape {@code m/44'/1237'/account'/0/0} (levels 4 and 5 non-hardened).
 * Nostr signs and does NIP-44 ECDH with one key; both use option 0, so that
 * shared key needs no exception in the check.
 */
public final class Binding {

    private static final int H = 0x80000000;
    private static final int KM_PURPOSE = Bip32KeyDerivator.mangle("keymaster");

    private static final Set<Integer> SIGN_ONLY =
            Set.of(KeyVault.FN_GET_PUBLIC_KEY, KeyVault.FN_SIGN);
    private static final Set<Integer> SIGN_AND_AGREE =
            Set.of(KeyVault.FN_GET_PUBLIC_KEY, KeyVault.FN_SIGN, KeyVault.FN_KEY_AGREEMENT);
    private static final Set<Integer> AGREE_ONLY =
            Set.of(KeyVault.FN_GET_PUBLIC_KEY, KeyVault.FN_KEY_AGREEMENT);

    private enum Shape { OUR_TREE, NOSTR, X509, STANDARD }

    private record Pair(Alg alg, int option) {
    }

    private record Row(String name, int purpose, int level2, Set<Pair> pairs, Set<Integer> fns, Shape shape) {
        boolean matches(int[] path) {
            return path.length >= 2 && path[0] == (purpose | H) && path[1] == (level2 | H);
        }
    }

    private static final List<Row> ROWS = List.of(
            new Row("Nostr", 44, Protocol.NOSTR.coinType(),
                    Set.of(new Pair(Alg.SECP256K1, 0)), SIGN_AND_AGREE, Shape.NOSTR),
            new Row("SSH", 44, Protocol.SSH.coinType(),
                    Set.of(new Pair(Alg.ED25519, 0), new Pair(Alg.P256, 0)), SIGN_ONLY, Shape.OUR_TREE),
            new Row("OpenPGP", 44, Protocol.OPENPGP.coinType(),
                    Set.of(new Pair(Alg.ED25519, 0)), SIGN_AND_AGREE, Shape.OUR_TREE),
            new Row("X.509", 44, Protocol.X509.coinType(),
                    Set.of(new Pair(Alg.P256, 0)), SIGN_AND_AGREE, Shape.X509),
            new Row("MLS", 44, Protocol.MLS.coinType(),
                    Set.of(new Pair(Alg.ED25519, 0), new Pair(Alg.P256, 0)), SIGN_AND_AGREE, Shape.OUR_TREE),
            new Row("realms", KM_PURPOSE, 1,
                    Set.of(new Pair(Alg.SECP256K1, 0)), SIGN_AND_AGREE, Shape.OUR_TREE),
            new Row("Taproot", 86, 0,
                    Set.of(new Pair(Alg.SECP256K1, KeyVault.OPT_SECP256K1_TAPROOT)), SIGN_ONLY, Shape.STANDARD),
            new Row("SegWit", 84, 0,
                    Set.of(new Pair(Alg.SECP256K1, KeyVault.OPT_SECP256K1_ECDSA)), SIGN_ONLY, Shape.STANDARD));

    private Binding() {
    }

    /**
     * @return {@link VaultResult#OK} if the call is allowed on this path, otherwise
     *         {@link VaultResult#ERR_INVALID_PATH}
     */
    public static int check(Alg alg, int fn, int option, int[] path) {
        for (Row row : ROWS) {
            if (row.matches(path)) {
                return checkRow(row, alg, fn, option, path) ? VaultResult.OK : VaultResult.ERR_INVALID_PATH;
            }
        }
        return VaultResult.OK;
    }

    private static boolean checkRow(Row row, Alg alg, int fn, int option, int[] path) {
        if (!row.pairs().contains(new Pair(alg, option))) {
            return false;
        }
        return switch (row.shape()) {
            case STANDARD -> row.fns().contains(fn);
            case OUR_TREE -> row.fns().contains(fn) && ourTreeUse(path, option);
            case NOSTR -> row.fns().contains(fn) && (isNip06(path) || ourTreeUse(path, option));
            case X509 -> ourTreeUse(path, option) && x509RoleAllows(UseField.roleOf(path[3]), fn);
        };
    }

    /** First five levels hardened; {@code path[3]} reserved bits 0 and variant = option. */
    private static boolean ourTreeUse(int[] path, int option) {
        if (path.length < 5) {
            return false;
        }
        for (int i = 0; i < 5; i++) {
            if ((path[i] & H) == 0) {
                return false;
            }
        }
        int use = path[3] & 0x7FFFFFFF;
        return UseField.reservedBits(use) == 0 && UseField.variantOf(use) == option;
    }

    /** {@code m/44'/1237'/account'/0/i}: NIP-06, levels 4 and 5 non-hardened, change 0. */
    private static boolean isNip06(int[] path) {
        return path.length == 5
                && (path[2] & H) != 0
                && path[3] == 0
                && (path[4] & H) == 0;
    }

    private static boolean x509RoleAllows(int role, int fn) {
        Set<Integer> fns = switch (role) {
            case UseField.X509_CA, UseField.X509_TLS_SERVER,
                 UseField.X509_TLS_CLIENT, UseField.X509_CODE_SIGNING -> SIGN_ONLY;
            case UseField.X509_SMIME -> SIGN_AND_AGREE;
            case UseField.X509_SMIME_ENCRYPT -> AGREE_ONLY;
            default -> Set.of();
        };
        return fns.contains(fn);
    }
}
