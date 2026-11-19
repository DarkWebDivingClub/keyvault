# Protocol support

Which protocol operations each KeyVault can serve, and through which call of
the 0.6.0 API (`doc/api-0.6.0.md`).

| Vault | What it is |
|---|---|
| dkv00 v0.4.0 | The current software KeyVault (`Bip32KeyVault`), API 0.4.0 |
| dkv00 v0.6.0 | The same software KeyVault on the 0.6.0 API (SLIP-10, `alg` parameter), keyvault 0.6.0 |
| ckv01 | A Carbon KeyVault based on the Cryptnox v2.0 card, behind a 0.6.0 adapter |

Sources: dkv00 v0.4.0 and dkv00 v0.6.0 are checked against the code
(0.6.0: missions 48.1 and 48.2). "reserved" in the dkv00 v0.6.0 column means
the call is numbered and laid out but returns an error until a later,
non-breaking release. ckv01 is from Cryptnox's public documentation
(docs.cryptnox.com, v2.0) and has not been tested on a card.

## Legend

- **alg, fn, option**: the 0.6.0 call, one function per row. A protocol that
  needs two calls (for example a post-quantum hybrid) has two rows. `—` in
  alg means no `alg` value is defined yet.
- **option**: the number and the scheme it selects. A plain `0` means the
  key type has only one scheme for that function.
- **Status**: Best practice (use for new keys), Legacy (still in use, not for
  new keys), Future (post-quantum or new).
- **future**: reserved in the 0.6.0 API but not implemented yet (RSA and
  post-quantum). Whether it runs in software (Bouncy Castle) or through
  EXPORT is decided when we get there.
- **prim.**: the vault can do the operation, but KeyMaster has no protocol
  code for it yet.
- **✅\***: works, but with a **new key** (SLIP-10 Ed25519 instead of
  DER-6), so the user must re-publish the public key. A ✅ without a star
  keeps today's key or is new.

GET_PUBLIC_KEY is left out: every protocol uses it, and it works on every
vault wherever the key type is supported.

## Functions and options used

| fn | Code | alg | option |
|---|---|---|---|
| SIGN | 2 | SECP256K1 | 0 Schnorr, 1 Taproot (reserved), 2 ECDSA |
| SIGN | 2 | ED25519 | 0 Ed25519, 1 Tor blinded (reserved) |
| SIGN | 2 | P256 | 0 ECDSA |
| SIGN | 2 | RSA | 0 PKCS#1 v1.5, 1 PSS |
| SIGN | 2 | ML_DSA | 0 ML-DSA |
| KEY_AGREEMENT | 3 | SECP256K1 | 0 ECDH |
| KEY_AGREEMENT | 3 | ED25519 | 0 X25519 |
| KEY_AGREEMENT | 3 | P256 | 0 ECDH |
| DECAPSULATE | 4 | RSA | 0 PKCS#1 v1.5, 1 OAEP |
| DECAPSULATE | 4 | ML_KEM | 0 ML-KEM |
| MUSIG2_NONCE | 16, Bitcoin | SECP256K1 | 0 (reserved) |
| MUSIG2_SIGN | 17, Bitcoin | SECP256K1 | 0 (reserved) |

Codes 0–15 are generic. Codes 16 and up are defined per protocol: the vault
reads the protocol from the path prefix (purpose and level 2), so the same
code means a different function in each protocol.

## Table

| Protocol | Operation | Algorithm | Status | alg | fn | option | dkv00 v0.4.0 | dkv00 v0.6.0 | ckv01 |
|---|---|---|---|---|---|---|---|---|---|
| age | Decrypt file | X25519 | Best practice | ED25519 | KEY_AGREEMENT | 0 X25519 | ❌ | ✅ prim. | ❌ |
| age | Decrypt file, PQ part | ML-KEM-768 | Future | ML_KEM | DECAPSULATE | 0 | ❌ | future | ❌ |
| age | Decrypt file, classic part | X25519 | Future | ED25519 | KEY_AGREEMENT | 0 X25519 | ❌ | ✅ prim. | ❌ |
| Bitcoin | SegWit, legacy spend | secp256k1 ECDSA | Legacy (most common) | SECP256K1 | SIGN | 2 ECDSA | ❌ | ✅ | ✅ |
| Bitcoin | Taproot spend | secp256k1 Schnorr, tweaked | Best practice | SECP256K1 | SIGN | 1 Taproot | ❌ | reserved | ❌ unless a tweak is added |
| Bitcoin | BIP-360 (draft) | ML-DSA | Future | ML_DSA | SIGN | 0 | ❌ | future | ❌ |
| Ethereum | Transactions | secp256k1 ECDSA | Best practice | SECP256K1 | SIGN | 2 ECDSA | ❌ | ✅ | ✅ |
| GPG | Sign | Ed25519 | Best practice | ED25519 | SIGN | 0 Ed25519 | ✅ | ✅* | ✅ |
| GPG | Sign | RSA | Legacy | RSA | SIGN | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| GPG | Sign, PQ part | ML-DSA-65 | Future | ML_DSA | SIGN | 0 | ❌ | future | ❌ |
| GPG | Sign, classic part | Ed25519 | Future | ED25519 | SIGN | 0 Ed25519 | ❌ | ✅ | ✅ |
| GPG | Decrypt | X25519 | Best practice | ED25519 | KEY_AGREEMENT | 0 X25519 | ❌ no subkey | ✅ prim. | ❌ |
| GPG | Decrypt | RSA | Legacy | RSA | DECAPSULATE | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| GPG | Decrypt, PQ part | ML-KEM-768 | Future | ML_KEM | DECAPSULATE | 0 | ❌ | future | ❌ |
| GPG | Decrypt, classic part | X25519 | Future | ED25519 | KEY_AGREEMENT | 0 X25519 | ❌ | ✅ prim. | ❌ |
| IPsec (IKEv2) | Authenticate | P-256 ECDSA | Best practice | P256 | SIGN | 0 ECDSA | ❌ | ✅ | ✅ |
| IPsec (IKEv2) | Authenticate | P-384 ECDSA | Best practice (government) | — | SIGN | — | ❌ | ❌ | ❌ |
| IPsec (IKEv2) | Authenticate | Ed25519 | Future (strongSwan, libreswan only) | ED25519 | SIGN | 0 Ed25519 | ❌ | ✅ | ✅ |
| IPsec (IKEv2) | Authenticate | RSA | Legacy (very common) | RSA | SIGN | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| IPsec (IKEv2) | Authenticate | RSA-PSS | Legacy | RSA | SIGN | 1 PSS | ❌ | future | ❌ |
| IPsec (IKEv2) | Authenticate | ML-DSA | Future (draft) | ML_DSA | SIGN | 0 | ❌ | future | ❌ |
| Lightning | Channel signatures | secp256k1 ECDSA | Best practice | SECP256K1 | SIGN | 2 ECDSA | ❌ | ✅ | ✅ |
| Lightning | Taproot channels, round 1 | MuSig2 nonce | Future | SECP256K1 | MUSIG2_NONCE | 0 | ❌ | reserved | ❌ |
| Lightning | Taproot channels, round 2 | MuSig2 partial signature | Future | SECP256K1 | MUSIG2_SIGN | 0 | ❌ | reserved | ❌ |
| Lightning | Node transport | secp256k1 ECDH | Best practice | SECP256K1 | KEY_AGREEMENT | 0 ECDH | ❌ | ✅ prim. | ❌ |
| Matrix | Device signing | Ed25519 | Best practice | ED25519 | SIGN | 0 Ed25519 | ❌ | ✅ prim. | ✅ |
| Matrix | Olm session | X25519 | Best practice | ED25519 | KEY_AGREEMENT | 0 X25519 | ❌ | ✅ prim. | ❌ |
| MLS | Sign | Ed25519 | Best practice | ED25519 | SIGN | 0 Ed25519 | ✅ | ✅* | ⚠️ ≤1200 bytes |
| MLS | Sign | P-256 ECDSA | Best practice (alt suite) | P256 | SIGN | 0 ECDSA | ❌ | ✅ | ✅ |
| MLS | HPKE | X25519 | Best practice | ED25519 | KEY_AGREEMENT | 0 X25519 | ✅ | ✅* | ❌ |
| MLS | HPKE, PQ part (X-Wing) | ML-KEM-768 | Future | ML_KEM | DECAPSULATE | 0 | ❌ | future | ❌ |
| MLS | HPKE, classic part (X-Wing) | X25519 | Future | ED25519 | KEY_AGREEMENT | 0 X25519 | ❌ | ✅ | ❌ |
| Nostr | Sign event | secp256k1 BIP-340 Schnorr | Best practice | SECP256K1 | SIGN | 0 Schnorr | ✅ | ✅ | ⚠️ BIP-340 unconfirmed |
| Nostr | DMs NIP-44 | secp256k1 ECDH | Best practice | SECP256K1 | KEY_AGREEMENT | 0 ECDH | ✅ | ✅ | ❌ |
| Nostr | DMs NIP-04 | secp256k1 ECDH | Legacy | SECP256K1 | KEY_AGREEMENT | 0 ECDH | ✅ | ✅ | ❌ |
| Nostr | NIP-46 bunker, sign | secp256k1 BIP-340 Schnorr | Best practice | SECP256K1 | SIGN | 0 Schnorr | ✅ | ✅ | ⚠️ BIP-340 unconfirmed |
| Nostr | NIP-46 bunker, encrypt channel | secp256k1 ECDH | Best practice | SECP256K1 | KEY_AGREEMENT | 0 ECDH | ✅ | ✅ | ❌ |
| Our transport | Session to workstation | secp256k1 ECDH | Best practice | SECP256K1 | KEY_AGREEMENT | 0 ECDH | ✅ | ✅ | ❌ |
| SSH | Login | Ed25519 | Best practice | ED25519 | SIGN | 0 Ed25519 | ✅ | ✅* | ✅ |
| SSH | Login | P-256 ECDSA | Best practice (alt) | P256 | SIGN | 0 ECDSA | ❌ | ✅ | ✅ |
| SSH | Login (`rsa-sha2-256`, `-512`) | RSA | Legacy | RSA | SIGN | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| Tor onion v3 | Identity | Ed25519 | Best practice | ED25519 | SIGN | 0 Ed25519 | ❌ | ✅ prim. | ✅ |
| Tor onion v3 | Descriptors | Ed25519, blinded key | Best practice | ED25519 | SIGN | 1 Tor blinded | ❌ | reserved | ❌ |
| WireGuard | Handshake | X25519 | Best practice | ED25519 | KEY_AGREEMENT | 0 X25519 | ❌ | ✅ prim. | ❌ |
| WireGuard | Rosenpass PSK | ML-KEM | Future | ML_KEM | DECAPSULATE | 0 | ❌ | future | ❌ |
| X.509: code signing | Sign artefact | P-256 ECDSA | Best practice | P256 | SIGN | 0 ECDSA | ❌ | ✅ (no EV) | ✅ (no EV) |
| X.509: code signing | Sign artefact | RSA | Legacy (EV often) | RSA | SIGN | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| X.509: code signing | Sign artefact | ML-DSA | Future | ML_DSA | SIGN | 0 | ❌ | future | ❌ |
| X.509: document signing | PDF, eIDAS | P-256 ECDSA | Best practice | P256 | SIGN | 0 ECDSA | ❌ | ✅ (not qualified) | ✅ (not qualified) |
| X.509: document signing | PDF, eIDAS | Brainpool P-256 | Best practice (EU eID) | — | SIGN | — | ❌ | ❌ | ❌ |
| X.509: document signing | PDF, eIDAS | RSA | Legacy | RSA | SIGN | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| X.509: document signing | PDF, eIDAS | RSA-PSS | Legacy | RSA | SIGN | 1 PSS | ❌ | future | ❌ |
| X.509: PIV | OS smart-card login | P-256 ECDSA | Best practice | P256 | SIGN | 0 ECDSA | ❌ | ❌ needs a PIV interface | ❌ |
| X.509: PIV | OS smart-card login | RSA | Legacy | RSA | SIGN | 0 PKCS#1 v1.5 | ❌ | ❌ needs a PIV interface | ❌ |
| X.509: S/MIME | Sign mail | P-256 ECDSA | Best practice | P256 | SIGN | 0 ECDSA | ❌ | ✅ | ✅ |
| X.509: S/MIME | Sign mail | RSA | Legacy (dominant) | RSA | SIGN | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| X.509: S/MIME | Sign mail | RSA-PSS | Legacy | RSA | SIGN | 1 PSS | ❌ | future | ❌ |
| X.509: S/MIME | Decrypt mail | P-256 ECDH, roles 4 `smime` and 5 `smime-encrypt` | Best practice | P256 | KEY_AGREEMENT | 0 ECDH | ❌ | ✅ prim. | ❌ |
| X.509: S/MIME | Decrypt mail | RSA | Legacy (dominant) | RSA | DECAPSULATE | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| X.509: S/MIME | Decrypt mail | RSA-OAEP | Legacy | RSA | DECAPSULATE | 1 OAEP | ❌ | future | ❌ |
| X.509: S/MIME | Decrypt mail | ML-KEM | Future | ML_KEM | DECAPSULATE | 0 | ❌ | future | ❌ |
| X.509: TLS client, mTLS | Authenticate | P-256 ECDSA | Best practice | P256 | SIGN | 0 ECDSA | ❌ | ✅ | ✅ |
| X.509: TLS client, mTLS | Authenticate | P-384 ECDSA | Best practice (government) | — | SIGN | — | ❌ | ❌ | ❌ |
| X.509: TLS client, mTLS | Authenticate | Ed25519 | Future (poor support) | ED25519 | SIGN | 0 Ed25519 | ❌ | ✅ | ✅ |
| X.509: TLS client, mTLS | Authenticate, TLS 1.3 | RSA-PSS | Legacy | RSA | SIGN | 1 PSS | ❌ | future | ❌ |
| X.509: TLS client, mTLS | Authenticate, TLS 1.2 | RSA | Legacy | RSA | SIGN | 0 PKCS#1 v1.5 | ❌ | future | ❌ |
| X.509: TLS client, mTLS | Authenticate | ML-DSA | Future | ML_DSA | SIGN | 0 | ❌ | future | ❌ |

## Excluded

- **DSA.** OpenSSH removed it in 9.8 (2024), and FIPS 186-5 no longer
  allows it for new signatures.
- **Finite-field DH and ElGamal.** Only found in old GPG keys. Modern use
  (TLS FFDHE, IKE) is ephemeral and never touches a vault.
- **Ephemeral key exchange** in IPsec, TLS and SSH, including their
  post-quantum variants. The protocol daemon makes and discards those keys;
  only the long-term identity key reaches the vault.

## Gaps

**dkv00 v0.6.0**

- P-384 and Brainpool need new `alg` values (a new root each; P-384 has no
  SLIP-10 label).
- PIV needs a PIV card interface that Windows and macOS talk to directly. It
  is not a KeyVault function.
- The MuSig2 functions keep state (the nonce). In the software vault that
  state will live in app storage. FIDO_SIGN, which keeps a counter, was
  dropped from 0.6.0 and comes later as a new protocol with its own coin type.
- RSA and post-quantum are future: reserved in the API, not in the next
  KeyMaster release.

**ckv01**

- Every KEY_AGREEMENT and DECAPSULATE row fails: no raw ECDH on derived
  keys. This removes the NIP-46 bunker, Nostr DMs, MLS HPKE and our
  workstation transport, so ckv01 alone cannot run KeyMaster.
- Taproot needs the card to accept a merkle root (tweak) on SIGN; Tor
  descriptors need it to accept blinding parameters.
- BIP-340 exactness of its Schnorr signature is unconfirmed.
- Ed25519 input is capped at 1200 bytes, which MLS commits can exceed.
- No RSA, P-384, Brainpool, post-quantum, FIDO_SIGN or MuSig2, and no EXPORT
  as a fallback.

With SLIP-10, every signing key ckv01 derives matches dkv00 v0.6.0 for the
same seed and path (to be confirmed with a test vector). A user can move
between them without rotating signing keys.
