package club.dwdc.keyvault.core;

/**
 * The {@code alg} parameter of {@link KeyVault#execute}: selects the derivation
 * root and the key type (API 0.6.0, section 3).
 *
 * <p>The codes are frozen. They are what a card encodes in the APDU P1 byte, so
 * they must never be renumbered. They are unrelated to the 0.5.x {@code AlgField}
 * values, which the vault no longer reads from the path.
 *
 * <p>{@code RSA}, {@code ML_DSA} and {@code ML_KEM} are reserved: their codes are
 * fixed, but the 0.6.0 vault has no root for them and returns
 * {@link VaultResult#ERR_UNSUPPORTED_ALGORITHM}.
 */
public enum Alg {

    /** secp256k1. SLIP-10 root {@code "Bitcoin seed"}, identical to BIP-32. */
    SECP256K1(0, "Bitcoin seed"),

    /** Ed25519, and X25519 derived from it. SLIP-10 root {@code "ed25519 seed"}. Hardened only. */
    ED25519(1, "ed25519 seed"),

    /** NIST P-256. SLIP-10 root {@code "Nist256p1 seed"}. */
    P256(2, "Nist256p1 seed"),

    /** RSA. Reserved; root to be defined. */
    RSA(3, null),

    /** ML-DSA (FIPS 204). Reserved; root to be defined. */
    ML_DSA(4, null),

    /** ML-KEM (FIPS 203). Reserved; root to be defined. */
    ML_KEM(5, null);

    private final int code;
    private final String label;

    Alg(int code, String label) {
        this.code = code;
        this.label = label;
    }

    /** The frozen wire code (APDU P1). */
    public int code() {
        return code;
    }

    /** The SLIP-10 master HMAC key, or {@code null} for a reserved algorithm. */
    public String label() {
        return label;
    }

    /** Whether the 0.6.0 vault implements this algorithm. */
    public boolean isSupported() {
        return label != null;
    }

    /** The algorithm with this wire code, or {@code null} if no algorithm has it. */
    public static Alg fromCode(int code) {
        for (Alg alg : values()) {
            if (alg.code == code) {
                return alg;
            }
        }
        return null;
    }
}
