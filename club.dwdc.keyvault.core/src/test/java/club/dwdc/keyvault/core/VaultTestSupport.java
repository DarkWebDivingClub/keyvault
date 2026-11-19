package club.dwdc.keyvault.core;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import java.math.BigInteger;

/** Shared constants and helpers for the 0.6.0 tests. */
final class VaultTestSupport {

    static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    static final int H = 0x80000000;

    static final int NOSTR = Protocol.NOSTR.coinType();
    static final int SSH = Protocol.SSH.coinType();
    static final int OPENPGP = Protocol.OPENPGP.coinType();
    static final int X509 = Protocol.X509.coinType();
    static final int WIREGUARD = Protocol.WIREGUARD.coinType();
    static final int MLS = Protocol.MLS.coinType();
    static final int KM_PURPOSE = Bip32KeyDerivator.mangle("keymaster");

    private VaultTestSupport() {
    }

    /** {@code m/44'/coin'/identity'/use'/0'} with {@code use = variant << 8 | role}. */
    static int[] ourPath(int coin, int identity, int variant, int role) {
        return new int[]{44 | H, coin | H, identity | H, new UseField(variant, role).toIndex() | H, H};
    }

    /** Public key as SLIP-10 vectors print it (compressed for Weierstrass, 32 bytes for Ed25519). */
    static byte[] publicKeyCompressed(Alg alg, byte[] key) {
        if (alg == Alg.ED25519) {
            return new EdDSAPrivateKeySpec(key, EdDSANamedCurveTable.getByName("Ed25519")).getA().toByteArray();
        }
        return Slip10KeyDerivator.domain(alg).getG().multiply(new BigInteger(1, key)).normalize().getEncoded(true);
    }
}
