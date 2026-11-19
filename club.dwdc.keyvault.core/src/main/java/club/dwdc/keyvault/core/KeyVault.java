package club.dwdc.keyvault.core;

/**
 * The KeyVault API 0.6.0 ({@code doc/api-0.6.0.md}).
 *
 * <pre>
 * VaultResult execute(Alg alg, int fn, int option, byte[] payload, int... path)
 * </pre>
 *
 * <ul>
 *   <li>{@code alg} selects the SLIP-10 root and the key type (section 3).</li>
 *   <li>{@code fn} selects the operation (section 4). Codes 0–15 are generic;
 *       16 and up are a separate namespace per protocol.</li>
 *   <li>{@code option} selects the scheme when a key type has more than one,
 *       0–255, default 0 (section 5). On our own trees it must equal the
 *       {@code variant} of {@code path[3]}, so each scheme has its own key.
 *       {@code GET_PUBLIC_KEY} takes the option of the scheme the key is for.</li>
 *   <li>{@code payload} has a fixed layout per {@code (alg, fn, option)}; the
 *       vault checks its exact length first.</li>
 *   <li>{@code path} selects the key. It carries no algorithm (section 6).</li>
 * </ul>
 *
 * <p>All numbers here are frozen: later features arrive as new values, never
 * as renumbering.
 */
public interface KeyVault {

    // ── Generic functions (0–15) ─────────────────────────────────────────

    /**
     * Hand out the leaf private key. Only for algorithms the vault does not
     * support (B5); in 0.6.0 that is none, so it always fails:
     * {@code ERR_INVALID_PATH} on a path with a non-hardened level, otherwise
     * {@code ERR_UNSUPPORTED_ALGORITHM}.
     */
    int FN_EXPORT = 0;

    /** Public key of the leaf, with the chain code. Payload empty. */
    int FN_GET_PUBLIC_KEY = 1;

    /** Sign the payload. Signatures are raw and fixed-length. */
    int FN_SIGN = 2;

    /** Combine the leaf private key with a peer public key; raw shared secret. */
    int FN_KEY_AGREEMENT = 3;

    /** Recover a shared secret from a KEM ciphertext (ML-KEM) or RSA. Reserved. */
    int FN_DECAPSULATE = 4;

    // ── Protocol-specific functions (16+) ────────────────────────────────

    /** Bitcoin (coin type 0): MuSig2 round 1. Reserved. */
    int FN_MUSIG2_NONCE = 16;

    /** Bitcoin (coin type 0): MuSig2 round 2. Reserved. */
    int FN_MUSIG2_SIGN = 17;

    // ── Options per (alg, fn) ────────────────────────────────────────────

    /** The default scheme of every key type. */
    int OPT_DEFAULT = 0;

    /** {@code SECP256K1 SIGN}: BIP-340 Schnorr, 32-byte hash → 64 bytes. */
    int OPT_SECP256K1_SCHNORR = 0;

    /** {@code SECP256K1 SIGN}: BIP-341 Taproot tweaked Schnorr. Reserved. */
    int OPT_SECP256K1_TAPROOT = 1;

    /** {@code SECP256K1 SIGN}: ECDSA low-S, 32-byte hash → 65 bytes {@code r‖s‖v}, v = 0 or 1. */
    int OPT_SECP256K1_ECDSA = 2;

    /** {@code ED25519 SIGN}: pure Ed25519 (RFC 8032), raw message → 64 bytes. */
    int OPT_ED25519_PURE = 0;

    /** {@code ED25519 SIGN}: Tor v3 blinded key. Reserved. */
    int OPT_ED25519_TOR_BLINDED = 1;

    /** {@code P256 SIGN}: ECDSA low-S, 32-byte hash → 64 bytes {@code r‖s}. */
    int OPT_P256_ECDSA = 0;

    /**
     * Execute a function on the key at {@code path} under the root of {@code alg}.
     *
     * @param alg     root and key type
     * @param fn      operation ({@code FN_*})
     * @param option  scheme ({@code OPT_*}), 0–255
     * @param payload data for the operation; empty or null for {@code GET_PUBLIC_KEY}
     * @param path    derivation path (bit 31 = hardened)
     * @return status, output bytes and, for {@code GET_PUBLIC_KEY}, the chain code
     */
    VaultResult execute(Alg alg, int fn, int option, byte[] payload, int... path);
}
