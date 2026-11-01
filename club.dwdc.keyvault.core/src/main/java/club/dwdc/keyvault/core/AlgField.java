package club.dwdc.keyvault.core;

/**
 * Level 4: alg(15 bits) | variant(8 bits) | role(8 bits) = 31 bits
 *
 * Bit 31        Bit 0
 * H | alg(30-16) | variant(15-8) | role(7-0)
 *
 * alg     - global algorithm table (ALG_* below).
 * variant - parameter set within the algorithm:
 *             Schnorr, Ed25519: always 0 (one curve each)
 *             RSA:   key size / 256
 *             ECDSA: the curve - 0 secp256k1, 1 P-256, 2 P-384, 3 P-521,
 *                    4 Brainpool P256r1, 5 Brainpool P384r1, 6 Brainpool P512r1.
 *                    Direct-key derivation (32-byte leaf mod n) works only for
 *                    0, 1 and 4; the vault implements 0 and 1.
 * role    - defined per protocol. ROLE_SIGN = 0 is role 0 of the SSH
 *           (user authentication), Nostr (identity) and MLS (signing) paths.
 *           ROLE_HPKE = 1 is a named constant intended for MLS HPKE keys;
 *           no role table defines it yet. Other protocols (e.g. X.509,
 *           OpenPGP) define their own numbers.
 *           See doc/key-derivation.md in keymaster-wks.
 */
public record AlgField(int alg, int variant, int role) {

    public int toIndex() {
        return ((alg & 0x7FFF) << 16) | ((variant & 0xFF) << 8) | (role & 0xFF);
    }

    // Convenience constants
    public static final int ALG_SCHNORR = 0;
    public static final int ALG_ED25519 = 1;
    public static final int ALG_RSA     = 2;
    public static final int ALG_ECDSA   = 3;

    // Conveniences only - see "role" above. Not a global role table.
    public static final int ROLE_SIGN = 0;
    public static final int ROLE_HPKE = 1;
}
