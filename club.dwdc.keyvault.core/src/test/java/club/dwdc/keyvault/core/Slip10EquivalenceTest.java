package club.dwdc.keyvault.core;

import org.bitcoinj.crypto.DeterministicKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static club.dwdc.keyvault.core.VaultTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 48.1 step 3, the secp256k1 guard: SLIP-10 under {@link Alg#SECP256K1} equals
 * bitcoinj BIP-32 ({@link Bip32KeyDerivator}) on every path shape KeyMaster
 * uses, hardened and non-hardened. This is what keeps Nostr npubs, realm xpubs,
 * the avatar login xpub and transport keys unchanged in 0.6.0.
 */
class Slip10EquivalenceTest {

    private final Bip32KeyDerivator bip32 = new Bip32KeyDerivator(MNEMONIC);
    private final Slip10KeyDerivator slip10 = Slip10KeyDerivator.fromMnemonic(MNEMONIC, "");

    private static List<int[]> paths() {
        int alice = Bip32KeyDerivator.mangle("alice@atlanta.com");
        return List.of(
                new int[]{44 | H, NOSTR | H, H, H, H},                       // Nostr default
                new int[]{44 | H, NOSTR | H, alice | H, H, H},               // Nostr named identity
                new int[]{44 | H, 0 | H, H, H, H},                           // Bitcoin default (GoldenPathTest)
                new int[]{44 | H, 0 | H, H, 1 | H, H},                       // Bitcoin change (GoldenPathTest)
                new int[]{44 | H, NOSTR | H, H, 0, 0},                       // NIP-06 shape
                new int[]{84 | H, H, H, 0, 5},                               // BIP-84
                new int[]{KM_PURPOSE | H, 1 | H, 7 | H, H, 12345 | H},       // realm connector
                new int[]{KM_PURPOSE | H, 1 | H, 7 | H, H, 12345 | H,
                        Bip32KeyDerivator.mangle("ssh"), 3});                // realm service channel
    }

    @Test
    void privateKeyAndChainCodeEqualBitcoinj() {
        for (int[] path : paths()) {
            DeterministicKey ref = bip32.deriveKey(path);
            Slip10KeyDerivator.Node node = slip10.deriveNode(Alg.SECP256K1, path);
            assertArrayEquals(ref.getPrivKeyBytes(), node.key(), "key at " + java.util.Arrays.toString(path));
            assertArrayEquals(ref.getChainCode(), node.chainCode(), "chain code at " + java.util.Arrays.toString(path));
        }
    }

    @Test
    void vaultPublicKeyEqualsBitcoinj() {
        Bip32KeyVault vault = new Bip32KeyVault(MNEMONIC);
        int[] realm = {KM_PURPOSE | H, 1 | H, 7 | H, H, 12345 | H};
        VaultResult r = vault.execute(Alg.SECP256K1, KeyVault.FN_GET_PUBLIC_KEY, 0, null, realm);
        assertTrue(r.isOk());
        DeterministicKey ref = bip32.deriveKey(realm);
        assertArrayEquals(ref.getPubKey(), r.data());
        assertArrayEquals(ref.getChainCode(), r.chainCode());
    }
}
