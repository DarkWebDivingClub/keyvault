package club.dwdc.keyvault.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pins every number of the 0.6.0 freeze list that lives in keyvault
 * ({@code doc/api-0.6.0.md}; umbrella mission 48, freeze list). A change here is
 * a breaking change and must fail a test.
 */
class NumbersTest {

    @Test
    void algCodesAndLabels() {
        assertEquals(6, Alg.values().length);
        assertAlg(Alg.SECP256K1, 0, "Bitcoin seed");
        assertAlg(Alg.ED25519, 1, "ed25519 seed");
        assertAlg(Alg.P256, 2, "Nist256p1 seed");
        assertAlg(Alg.RSA, 3, null);
        assertAlg(Alg.ML_DSA, 4, null);
        assertAlg(Alg.ML_KEM, 5, null);
        assertNull(Alg.fromCode(6));
        assertNull(Alg.fromCode(-1));
    }

    private static void assertAlg(Alg alg, int code, String label) {
        assertEquals(code, alg.code(), alg.name());
        assertEquals(label, alg.label(), alg.name());
        assertEquals(label != null, alg.isSupported(), alg.name());
        assertSame(alg, Alg.fromCode(code));
    }

    @Test
    void functionCodes() {
        assertEquals(0, KeyVault.FN_EXPORT);
        assertEquals(1, KeyVault.FN_GET_PUBLIC_KEY);
        assertEquals(2, KeyVault.FN_SIGN);
        assertEquals(3, KeyVault.FN_KEY_AGREEMENT);
        assertEquals(4, KeyVault.FN_DECAPSULATE);
        assertEquals(16, KeyVault.FN_MUSIG2_NONCE);
        assertEquals(17, KeyVault.FN_MUSIG2_SIGN);
    }

    @Test
    void optionCodes() {
        assertEquals(0, KeyVault.OPT_DEFAULT);
        assertEquals(0, KeyVault.OPT_SECP256K1_SCHNORR);
        assertEquals(1, KeyVault.OPT_SECP256K1_TAPROOT);
        assertEquals(2, KeyVault.OPT_SECP256K1_ECDSA);
        assertEquals(0, KeyVault.OPT_ED25519_PURE);
        assertEquals(1, KeyVault.OPT_ED25519_TOR_BLINDED);
        assertEquals(0, KeyVault.OPT_P256_ECDSA);
    }

    @Test
    void errorCodes() {
        assertEquals(0, VaultResult.OK);
        assertEquals(1, VaultResult.ERR_UNSUPPORTED_FUNCTION);
        assertEquals(2, VaultResult.ERR_INVALID_PATH);
        assertEquals(3, VaultResult.ERR_INVALID_PAYLOAD);
        assertEquals(4, VaultResult.ERR_UNSUPPORTED_ALGORITHM);
        assertEquals(5, VaultResult.ERR_CRYPTO_FAILURE);
    }

    @Test
    void useFieldLayout() {
        // bits 30-16 reserved 0, variant 15-8, role 7-0
        assertEquals(0x0000, new UseField(0, 0).toIndex());
        assertEquals(0x0002, new UseField(0, 2).toIndex());
        assertEquals(0x0201, new UseField(2, 1).toIndex());
        assertEquals(0xFFFF, new UseField(255, 255).toIndex());
        int legacyX509 = 0x30102 | 0x80000000; // 0.5.x X.509 tls-client
        assertEquals(3, UseField.reservedBits(legacyX509));
        assertEquals(1, UseField.variantOf(legacyX509));
        assertEquals(2, UseField.roleOf(legacyX509));
        assertThrows(IllegalArgumentException.class, () -> new UseField(256, 0));
        assertThrows(IllegalArgumentException.class, () -> new UseField(0, -1));
    }

    @Test
    void x509Roles() {
        assertEquals(0, UseField.X509_CA);
        assertEquals(1, UseField.X509_TLS_SERVER);
        assertEquals(2, UseField.X509_TLS_CLIENT);
        assertEquals(3, UseField.X509_CODE_SIGNING);
        assertEquals(4, UseField.X509_SMIME);
        assertEquals(5, UseField.X509_SMIME_ENCRYPT);
    }

    @Test
    void coinTypes() {
        assertEquals(0, Protocol.BITCOIN.coinType());
        assertEquals(1237, Protocol.NOSTR.coinType());
        assertEquals(1238, Protocol.SSH.coinType());
        assertEquals(1239, Protocol.OPENPGP.coinType());
        assertEquals(1240, Protocol.X509.coinType());
        assertEquals(1241, Protocol.WIREGUARD.coinType());
        assertEquals(1242, Protocol.MLS.coinType());
    }

    @Test
    void configFieldLayout() {
        // cfg: csprng 30-24, index 23-0
        assertEquals(0x03000005, new ConfigField(ConfigField.CSPRNG_CHACHA20, 5).toIndex());
    }

    @Test
    void realmPurpose() {
        assertEquals(0x53C20D30, Bip32KeyDerivator.mangle("keymaster"));
    }
}
