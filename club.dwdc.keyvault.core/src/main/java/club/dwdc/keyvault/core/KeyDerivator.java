package club.dwdc.keyvault.core;

/**
 * Derives a 32-byte leaf private key from a path under the root of an
 * algorithm (SLIP-10, API 0.6.0).
 *
 * Each element in the path is a full 32-bit child number
 * (bit 31 = hardened flag, bits 30-0 = index).
 */
public interface KeyDerivator {

    byte[] derive(Alg alg, int... path);
}
