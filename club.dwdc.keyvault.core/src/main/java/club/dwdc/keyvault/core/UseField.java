package club.dwdc.keyvault.core;

/**
 * Level 4 ({@code use'}, {@code path[3]}) on our own trees, API 0.6.0:
 *
 * <pre>
 * Bit 31        Bit 0
 * H | reserved(30-16) = 0 | variant(15-8) | role(7-0)
 * </pre>
 *
 * <ul>
 *   <li><b>reserved</b> — must be 0. In 0.5.x these bits held the algorithm;
 *       the vault now takes the algorithm from the {@code alg} parameter and the
 *       binding check refuses a non-zero value.</li>
 *   <li><b>variant</b> — must equal the {@code option} of the call, so each
 *       scheme has its own key.</li>
 *   <li><b>role</b> — defined per protocol (for example SSH 0; OpenPGP
 *       0 certification, 1 signing, 2 encryption; MLS 0 signing, 1 HPKE;
 *       X.509 {@link #X509_CA} … {@link #X509_SMIME_ENCRYPT}). There is no
 *       global role table.</li>
 * </ul>
 *
 * Replaces {@code AlgField} (0.5.x).
 */
public record UseField(int variant, int role) {

    public UseField {
        if (variant < 0 || variant > 0xFF) {
            throw new IllegalArgumentException("variant must be 0-255: " + variant);
        }
        if (role < 0 || role > 0xFF) {
            throw new IllegalArgumentException("role must be 0-255: " + role);
        }
    }

    /** The unhardened index; OR with {@code 0x80000000} for the path. */
    public int toIndex() {
        return (variant << 8) | role;
    }

    /** Bits 30–16 of a {@code path[3]} value; 0 on a valid 0.6.0 path. */
    public static int reservedBits(int index) {
        return (index & 0x7FFFFFFF) >>> 16;
    }

    /** Bits 15–8 of a {@code path[3]} value. */
    public static int variantOf(int index) {
        return (index >>> 8) & 0xFF;
    }

    /** Bits 7–0 of a {@code path[3]} value. */
    public static int roleOf(int index) {
        return index & 0xFF;
    }

    // ── X.509 roles (frozen; new roles from 6, IPsec next) ───────────────

    public static final int X509_CA = 0;
    public static final int X509_TLS_SERVER = 1;
    public static final int X509_TLS_CLIENT = 2;
    public static final int X509_CODE_SIGNING = 3;
    /** S/MIME dual use: signs and decrypts (key agreement). */
    public static final int X509_SMIME = 4;
    /** S/MIME encryption only (two-certificate setup). */
    public static final int X509_SMIME_ENCRYPT = 5;
}
