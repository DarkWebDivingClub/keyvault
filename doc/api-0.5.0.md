# KeyVault API 0.5.0

Status: **proposal**, not implemented. Current release: 0.4.0.

0.5.0 is a breaking release. Pre-1.0 semver allows breaking changes in a
minor bump (`~/git/net.h3/doc/wow/branching-and-versioning.md`).

0.5.0 is the target for the next KeyMaster release (not KeyMaster 1.0.0) and
the KeyVault API we build on from here, including hardware vaults.

`RSA`, `ML_DSA` and `ML_KEM` are future: their `alg` values and options are
reserved here so the API does not break again when they arrive, but 0.5.0
does not implement them. Until then they return `ERR_UNSUPPORTED_ALGORITHM`.

## 1. Breaking changes

| # | Change | 0.4.0 | 0.5.0 | Who must change |
|---|---|---|---|---|
| B1 | Call signature | `execute(int function, byte[] payload, int... path)` | `execute(Alg alg, Function fn, int option, byte[] payload, int... path)` | Every caller |
| B2 | Where the algorithm comes from | Read from `path[3]` (`AlgField`, bits 30–16) | The `alg` parameter. The vault no longer reads the algorithm from the path | Every caller, `AlgField` |
| B3 | Ed25519 derivation | BIP-32 secp256k1 leaf private key used as the RFC 8032 seed (kv01 DER-6) | SLIP-10 from the `"ed25519 seed"` root | **All Ed25519 and X25519 keys change**: SSH, OpenPGP, MLS |
| B4 | `path[3]` on our own trees | algorithm (30–16), variant (15–8), role (7–0) | bits 30–16 reserved and MUST be 0; variant and role unchanged | Ed25519 paths change value (algorithm 1 removed). secp256k1 paths with algorithm 0 keep their value |
| B5 | EXPORT | `FN_EXPORT_SEED` returns the leaf private key for any path and algorithm | Renamed `EXPORT`. Refused for every `alg` the vault supports, and for non-hardened paths | Any caller that reads private keys (keyexporter) |
| B6 | Binding check | None | Known path prefixes accept only their listed `(alg, option)` pairs (section 6) | Callers that use a key outside its protocol |
| B7 | New functions | — | Generic: `DECAPSULATE` (4). Protocol-specific: `MUSIG2_NONCE`, `MUSIG2_SIGN` (Bitcoin), `FIDO_SIGN` (FIDO) | None (additive) |

Keys that **do not** change: Nostr, realms, the avatar login xpub
(`Realm.java:386`) and the transport key. They are secp256k1, where SLIP-10
equals BIP-32, and their `path[3]` value is unchanged.

KeyMaster has no public distribution yet (user story 01, Zapstore, is a
draft), so this break is taken without a legacy derivation. If one is needed
later, it is an extra `alg` value (`ED25519_LEGACY`) and nothing else changes.

## 2. The call

```java
VaultResult execute(Alg alg, Function fn, int option, byte[] payload, int... path)
```

| Parameter | Chooses | Section |
|---|---|---|
| `alg` | Root and key type | 3 |
| `fn` | Generic operation | 4 |
| `option` | Scheme, when the key type has a choice. 8 bits, enumerated, default 0 | 5 |
| `payload` | The data to operate on. Layout fixed by `(alg, fn, option)` | 5 |
| `path` | Which key | 6 |

The order is the order the vault works in: `alg` selects the root, `path`
walks to the leaf key, `fn` and `option` say what to do with it, and
`payload` is what it is done to.

The vault knows no protocol. Building the SSH session blob, the OpenPGP
packet, the Nostr event id or the Bitcoin sighash stays with the caller.

`KeyVault` is a high-level API. An implementation that talks to a card
(kv01) encodes each call as an APDU internally: INS = `fn`, P1 = `alg`,
P2 = `option`, data = path and payload. The card encoding is specified in
keyvault-sim `doc/requirements.md`, not here.

## 3. `alg`: root and key type

Derivation is SLIP-10. `alg` selects the HMAC key for the master:
`master = HMAC-SHA512(key = label, data = seed)`.

| `alg` | Label | Key type | Standard |
|---|---|---|---|
| `SECP256K1` | `Bitcoin seed` | secp256k1 | BIP-32, SLIP-10 |
| `ED25519` | `ed25519 seed` | Ed25519; X25519 derived from it | SLIP-10 |
| `P256` | `Nist256p1 seed` | NIST P-256 | SLIP-10 |
| `RSA` | to be defined (future) | RSA | ours |
| `ML_DSA` | to be defined (future) | ML-DSA | ours |
| `ML_KEM` | to be defined (future) | ML-KEM | ours |

Rules:

- Ed25519 and all non-curve roots are hardened-only.
- Non-curve roots: the leaf seeds a deterministic key generator, selected
  by the `csprng` field of `cfg` (section 6). ML-DSA (FIPS 204) and ML-KEM
  (FIPS 203) are generated from a seed by definition. RSA needs the prime
  search procedure fixed exactly before it is implemented.
- The same path under different `alg` values gives unrelated keys.

X25519 is derived from the Ed25519 key as today: SHA-512 of the 32-byte
Ed25519 seed, first 32 bytes, clamped.

## 4. `fn`: operations

Only private-key operations are in the vault. Verify, encrypt and
encapsulate need only the public key and run outside.

| Code | `fn` | Does | Output |
|---|---|---|---|
| 0 | `EXPORT` | Hands out the leaf private key, only for `alg` values the vault does not support (B5) | Leaf private key |
| 1 | `GET_PUBLIC_KEY` | Public key of the leaf | Public key, and the chain code where the root has one |
| 2 | `SIGN` | Signs the payload | Signature (raw, section 5) |
| 3 | `KEY_AGREEMENT` | Combines the leaf private key with a peer public key | Raw shared secret. The caller applies its own KDF |
| 4 | `DECAPSULATE` | Recovers a shared secret from a KEM ciphertext (ML-KEM), or the content key (RSA) | Shared secret |
| 16+ | protocol-specific | Defined per protocol, see below | — |

Codes 0–3 keep their 0.4.0 values. Codes 0–15 are generic and mean the same
for every protocol.

### Protocol-specific functions (16+)

Codes 16 and up are a separate namespace per protocol. The vault takes the
protocol from the path prefix: the purpose and level 2. On BIP-44-shaped
trees level 2 is the coin type (`Protocol.java`); on the realm tree it is
the scheme version. So code 16 under Bitcoin and code 16 under FIDO are
different functions. A 16+ code on a
path whose protocol does not define it returns `ERR_UNSUPPORTED_FUNCTION`.

They exist only for operations that keep state on the vault between calls.
Stateless variants (Taproot tweak, Tor key blinding) are `option` values of
`SIGN`, not new functions.

| Protocol (coin type) | Code | `fn` | Does | Output |
|---|---|---|---|---|
| Bitcoin (0) | 16 | `MUSIG2_NONCE` | MuSig2 round 1: makes a secret nonce, keeps it on the vault, returns the public nonce | Public nonce |
| Bitcoin (0) | 17 | `MUSIG2_SIGN` | MuSig2 round 2: partial signature with the kept nonce, then deletes the nonce | Partial signature |
| FIDO (to be assigned) | 16 | `FIDO_SIGN` | Signs a FIDO assertion and increments a signature counter kept on the vault | Signature and counter |

This is the one place the vault knows about protocols: these operations
only make sense inside the protocol that defines them.

`EXPORT` never returns the seed, a master key or any key above the leaf.
Since each `alg` has its own root, an exported RSA or PQ key reveals nothing
about the curve keys the vault keeps.

## 5. `option` and payload layouts

`option` is 0 except where a key type has more than one scheme for the same
function. Values are enumerated per `(alg, fn)`; any other value returns
`UNSUPPORTED_ALGORITHM`. Flags never go in the payload.

| `alg` | `fn` | `option` | Scheme | Payload | Output |
|---|---|---|---|---|---|
| any | `GET_PUBLIC_KEY` | 0 | — | empty | public key |
| `SECP256K1` | `SIGN` | 0 | BIP-340 Schnorr | 32-byte hash | 64 bytes |
| `SECP256K1` | `SIGN` | 1 | BIP-340 Schnorr on the BIP-341 tweaked key | 32-byte sighash, then an optional 32-byte merkle root (empty = BIP-86) | 64 bytes |
| `SECP256K1` | `SIGN` | 2 | ECDSA, low-S | 32-byte hash | 65 bytes `r ‖ s ‖ v` (`v` = recovery id) |
| `SECP256K1` | `KEY_AGREEMENT` | 0 | ECDH, x-coordinate | peer key: 32 bytes x-only (even y) or 33 bytes compressed | 32 bytes |
| `ED25519` | `SIGN` | 0 | Pure Ed25519 (RFC 8032) | raw message | 64 bytes |
| `ED25519` | `SIGN` | 1 | Ed25519 with a Tor v3 blinded key | blinding parameters (time period number and length, 8 bytes each), then the message | 64 bytes |
| `ED25519` | `KEY_AGREEMENT` | 0 | X25519 | 32-byte peer key | 32 bytes |
| `P256` | `SIGN` | 0 | ECDSA, low-S | 32-byte hash | 64 bytes `r ‖ s` |
| `P256` | `KEY_AGREEMENT` | 0 | ECDH, x-coordinate | 33 or 65-byte peer key | 32 bytes |
| `RSA` | `SIGN` | 0 | PKCS#1 v1.5 | hash, with its algorithm identifier | modulus length |
| `RSA` | `SIGN` | 1 | PSS | hash | modulus length |
| `RSA` | `DECAPSULATE` | 0 | PKCS#1 v1.5 decryption | ciphertext | content key |
| `RSA` | `DECAPSULATE` | 1 | OAEP decryption | ciphertext | content key |
| `ML_DSA` | `SIGN` | 0 | ML-DSA (FIPS 204) | message | signature |
| `ML_KEM` | `DECAPSULATE` | 0 | ML-KEM (FIPS 203) | ciphertext | 32 bytes |

Rules:

- Payload fields have fixed lengths. Only the last field may be optional or
  variable. The vault checks the exact length first and returns
  `INVALID_PAYLOAD` otherwise.
- Signatures are raw and fixed-length. DER encoding is the caller's job.
- On hardware, Schnorr aux and ECDSA nonces SHOULD be random. The software
  vault keeps deterministic signing (zero aux for BIP-340, as today).
- Maximum Ed25519 message length: to be fixed with the card supplier.

The Taproot tweak is computed by the vault,
`t = tagged_hash("TapTweak", P ‖ merkle_root)`, so a caller can never
supply an arbitrary tweak. The Tor blinding factor is likewise computed by
the vault from its own public key and the time period, never supplied.

## 6. `path`: which key

The path carries no algorithm. On our own trees:

```
m / 44' / coin' / mangle(id)' / use' / cfg'
```

| Level | Field | Meaning |
|---|---|---|
| 1 | `44'` | BIP-44-shaped tree |
| 2 | `coin'` | Protocol (`Protocol.java`): 1237 Nostr, 1238 SSH, 1239 OpenPGP, 1240 X509, 1241 WireGuard, 1242 MLS |
| 3 | `mangle(id)'` | Identity: first 4 bytes of SHA-256(UTF-8 id), `& 0x7FFFFFFF` |
| 4 | `use'` | bits 30–16 reserved 0; 15–8 variant (MUST equal `option`); 7–0 role (0 SIGN, 1 HPKE, …) |
| 5 | `cfg'` | bits 30–24 csprng (`ConfigField`); 23–0 index (key generation) |

All levels are hardened.

The realm tree (`RealmPaths.java`) has its own shape:

```
m / mangle("keymaster")' / scheme' / realmId' / use' / mangle(login_xpub)'   ← connector key
  / mangle(service_type) / seq                                              ← service channel
```

The purpose is `mangle("keymaster")` = `0x53C20D30`, and level 2 is the
scheme version (1), not a coin type. The connector levels are hardened. The
two service-channel levels are **non-hardened** on purpose: the avatar
derives them from the exported connector xpub, holding no private key.

Level 3 is the "who" level on every BIP-44-shaped tree: `mangle(id)'`,
`realmId'` or `account'`. The vault never interprets it.

Standard trees keep their own layout: BIP-84 `m/84'/0'/account'/change/index`,
BIP-86 `m/86'/0'/account'/change/index`, Ethereum `m/44'/60'/0'/0/index`.
Their last two levels are non-hardened.

### Binding check

For known prefixes, the vault accepts only the listed pairs and returns
`INVALID_PATH` for anything else. Unknown prefixes are the caller's choice.

| Prefix | Allowed `(alg, option)` | Functions |
|---|---|---|
| `m/44'/1237'` Nostr | `(SECP256K1, 0)` | `GET_PUBLIC_KEY`, `SIGN`, `KEY_AGREEMENT` |
| `m/44'/1238'` SSH | `(ED25519, 0)`, `(P256, 0)` | `GET_PUBLIC_KEY`, `SIGN` |
| `m/44'/1239'` OpenPGP | `(ED25519, 0)` | `GET_PUBLIC_KEY`, `SIGN`, `KEY_AGREEMENT` |
| `m/44'/1242'` MLS | `(ED25519, 0)`, `(P256, 0)` | `GET_PUBLIC_KEY`, `SIGN`, `KEY_AGREEMENT` |
| `m/mangle("keymaster")'/1'` realms | `(SECP256K1, 0)` | `GET_PUBLIC_KEY`, `SIGN`, `KEY_AGREEMENT` |
| `m/86'/0'` Taproot | `(SECP256K1, 1)` | `GET_PUBLIC_KEY`, `SIGN` |
| `m/84'/0'` SegWit | `(SECP256K1, 2)` | `GET_PUBLIC_KEY`, `SIGN` |

On our own trees the check also requires `use'` variant = `option`, so each
scheme and each role has its own key. Nostr is the exception the protocol
forces: NIP-44 does ECDH with the signing key, so Schnorr and ECDH share one
key on `m/44'/1237'`.

`EXPORT` is never allowed on a path with a non-hardened level. A
non-hardened child private key plus the parent's chain code reveals the
parent key.

## 7. Errors

Unchanged from 0.4.0 (`VaultResult`):

| Code | Name | 0.5.0 use |
|---|---|---|
| 0 | `OK` | |
| 1 | `ERR_UNSUPPORTED_FUNCTION` | Unknown `fn`, or `fn` not defined for this `alg` |
| 2 | `ERR_INVALID_PATH` | Malformed path, binding check failed, `EXPORT` on a non-hardened path |
| 3 | `ERR_INVALID_PAYLOAD` | Wrong payload length or encoding |
| 4 | `ERR_UNSUPPORTED_ALGORITHM` | Unknown `alg` or `option`; `EXPORT` of a supported `alg` (as kv01 EXP-1) |
| 5 | `ERR_CRYPTO_FAILURE` | Invalid point, zero nonce, other arithmetic failure |

## 8. What the protocols get

The full per-protocol table, including the Cryptnox-based ckv01, is in
[protocol-support.md](protocol-support.md).

Legend: ✅* works, but with a **new key** (SLIP-10 replaces DER-6, so the
user must re-publish the public key). ✅ without a star keeps today's key or
is new in 0.5.0. "prim." means the vault can do it, but KeyMaster has no
protocol code for it yet. "future" means the call is reserved but not
implemented in 0.5.0 (RSA and post-quantum).

| Protocol | Operation | `alg` | `fn` | `option` | 0.4.0 | 0.5.0 |
|---|---|---|---|---|---|---|
| Nostr | Sign event | `SECP256K1` | `SIGN` | 0 Schnorr | ✅ | ✅ |
| Nostr | DMs | `SECP256K1` | `KEY_AGREEMENT` | 0 ECDH | ✅ | ✅ |
| Nostr | NIP-46 bunker, sign | `SECP256K1` | `SIGN` | 0 Schnorr | ✅ | ✅ |
| Nostr | NIP-46 bunker, encrypt channel | `SECP256K1` | `KEY_AGREEMENT` | 0 ECDH | ✅ | ✅ |
| Realms | Channel events | `SECP256K1` | `SIGN` | 0 Schnorr | ✅ | ✅ |
| Realms | Channel encryption | `SECP256K1` | `KEY_AGREEMENT` | 0 ECDH | ✅ | ✅ |
| Our transport | Session to workstation | `SECP256K1` | `KEY_AGREEMENT` | 0 ECDH | ✅ | ✅ |
| SSH | Login | `ED25519` | `SIGN` | 0 Ed25519 | ✅ | ✅* |
| SSH | Login | `P256` | `SIGN` | 0 ECDSA | ❌ | ✅ |
| SSH | FIDO login | `ED25519` | `FIDO_SIGN` | 0 | ❌ | ✅ |
| SSH | FIDO login | `P256` | `FIDO_SIGN` | 0 | ❌ | ✅ |
| OpenPGP | Sign | `ED25519` | `SIGN` | 0 Ed25519 | ✅ | ✅* |
| OpenPGP | Decrypt | `ED25519` | `KEY_AGREEMENT` | 0 X25519 | ❌ no subkey | ✅ prim. |
| MLS | Sign | `ED25519` | `SIGN` | 0 Ed25519 | ✅ | ✅* |
| MLS | HPKE | `ED25519` | `KEY_AGREEMENT` | 0 X25519 | ✅ | ✅* |
| Bitcoin | SegWit, legacy spend | `SECP256K1` | `SIGN` | 2 ECDSA | ❌ | ✅ |
| Bitcoin | Taproot spend | `SECP256K1` | `SIGN` | 1 Taproot | ❌ | ✅ |
| Lightning | Channel signatures | `SECP256K1` | `SIGN` | 2 ECDSA | ❌ | ✅ |
| Lightning | Taproot channels, round 1 | `SECP256K1` | `MUSIG2_NONCE` | 0 | ❌ | ✅ |
| Lightning | Taproot channels, round 2 | `SECP256K1` | `MUSIG2_SIGN` | 0 | ❌ | ✅ |
| Lightning | Node transport | `SECP256K1` | `KEY_AGREEMENT` | 0 ECDH | ❌ | ✅ prim. |
| Ethereum | Transactions | `SECP256K1` | `SIGN` | 2 ECDSA | ❌ | ✅ |
| X.509 | TLS, S/MIME, IPsec, code and document signing | `P256` | `SIGN` | 0 ECDSA | ❌ | ✅ |
| X.509 | S/MIME decrypt | `P256` | `KEY_AGREEMENT` | 0 ECDH | ❌ | ✅ |
| X.509 | Legacy RSA signing | `RSA` | `SIGN` | 0 PKCS#1 v1.5 | ❌ | future |
| X.509 | TLS 1.3, PAdES RSA signing | `RSA` | `SIGN` | 1 PSS | ❌ | future |
| X.509 | Legacy RSA decrypt | `RSA` | `DECAPSULATE` | 0 PKCS#1 v1.5 | ❌ | future |
| X.509 | RSA-OAEP decrypt | `RSA` | `DECAPSULATE` | 1 OAEP | ❌ | future |
| X.509 | PIV smart-card login | — | — | — | ❌ | ❌ needs a PIV interface |
| WireGuard | Handshake | `ED25519` | `KEY_AGREEMENT` | 0 X25519 | ❌ | ✅ prim. |
| age | Decrypt file | `ED25519` | `KEY_AGREEMENT` | 0 X25519 | ❌ | ✅ prim. |
| Tor onion v3 | Identity | `ED25519` | `SIGN` | 0 Ed25519 | ❌ | ✅ prim. |
| Tor onion v3 | Descriptors | `ED25519` | `SIGN` | 1 Tor blinded | ❌ | ✅ prim. |
| FIDO2, passkeys | Web login | `P256` | `FIDO_SIGN` | 0 | ❌ | ✅ |
| FIDO2, passkeys | Web login | `ED25519` | `FIDO_SIGN` | 0 | ❌ | ✅ |
| Post-quantum | Sign | `ML_DSA` | `SIGN` | 0 | ❌ | future |
| Post-quantum | Decrypt | `ML_KEM` | `DECAPSULATE` | 0 | ❌ | future |

With SLIP-10, every signing key also matches what a SLIP-10 card (such as
Cryptnox v2.0) derives from the same seed and path.

## 9. Code affected

| Repo | Where |
|---|---|
| keyvault | `KeyVault`, `Bip32KeyVault`, `Bip32KeyDerivator` (one root per `alg`, SLIP-10 Ed25519), `AlgField` (algorithm bits reserved), `KeyVaultIdentity` (nostr), tests |
| keymaster | `IdentityPaths`, `RealmPaths`, `Realm`, `SshServiceHandler`, `NostrServiceHandler`, `KeyMasterController`; `KVMetaStore` and `KeyMetaDataStore` store paths, so stored Ed25519 entries need migrating; tests |
| keyexporter | `OpenPgpSeedDeriver`, `KeyExporterMain`: derive OpenPGP keys themselves and must change in step |
| keymaster-android | Call sites; rebuild and redeploy per the Android sync checklist |
| keymaster-avatar | To check: whether it caches SSH or GPG public keys on the workstation |
| keymaster-e2e-test | Fixed key vectors |
| keyvault-sim | `doc/requirements.md` DER-1, DER-4, DER-5, DER-6 and EXP-1..3 follow this once the hold is lifted |

## 10. Open

- Future: labels and generators for the `RSA`, `ML_DSA` and `ML_KEM` roots,
  and whether they run in software (Bouncy Castle) or go through `EXPORT`.
- Final `option` numbering and the full role list.
- Ed25519 maximum message length on the card.
