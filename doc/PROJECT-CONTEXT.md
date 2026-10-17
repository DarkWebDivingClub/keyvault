# Project Context

Updated: 2026-06-14

Use this document to resume work after restarting the development environment.
It records project decisions and repository state, not secrets.

## Repositories

- `/home/rene/git/club.dwdc.keyvault`
  - KeyVault cryptographic library and architecture documentation.
  - GitHub: `DarkWebDivingClub/club.dwdc.keyvault`
  - Branch: `master`
- `/home/rene/git/club.dwdc.keymaster.android`
  - Android KeyMaster application.
  - GitHub: `DarkWebDivingClub/club.dwdc.keymaster.android`
  - Branch: `master`
- `/home/rene/git/club.dwdc.keyexporter`
  - Java OpenPGP key export tool.
  - Version: `0.1.0`
  - GitHub: `DarkWebDivingClub/club.dwdc.keyexporter`
  - Branch: `main`

The namespace is `club.dwdc`, not `org.dwdc`.

## Git Identity

Repositories matching `/home/rene/git/club.*` use:

```text
Name: Rene Malmgren
Email: duke_h3@dwdc.club
Signing key: 9AAEEDE389575546090A557CB10C7BD445AB95B9
Signed commits: required
```

All three repositories use `GPL-3.0-only`.

Do not add automated assistant co-author trailers to commits.

## Current Checkpoint

The KeyVault architecture checkpoint was committed and pushed:

```text
0ee5faa894d40d38f7154035bcdba2ec2bce018c
docs: define key system architecture
```

The commit has a valid GPG signature from
`Rene Malmgren <duke_h3@dwdc.club>`.

## Architecture

The current architecture is documented in
[ARCHITECTURE.md](ARCHITECTURE.md).

Main responsibilities:

- **KeyVault** deterministically derives keys and performs constrained
  cryptographic operations.
- **KeyMaster** is the controller and security authority. It owns identity
  metadata, active protocol assignments, policy, approval, and audit data.
- **Avatar** represents KeyMaster on a target host and maintains one
  connection to KeyMaster through the host's Nostr relay.
- **Avatar services** expose native host interfaces and communicate with
  Avatar over a local socket.

Expected implementation languages:

- KeyMaster services: Java.
- Android KeyMaster GUI: Kotlin.
- Avatar and most Avatar services: Rust.

KeyMaster and Avatar each use one WebSocket connection to the Nostr relay.
Protocol service messages are multiplexed over those connections. Individual
services do not open separate Nostr or TCP connections.

## Identity and Key Activation

The deterministic seed makes protocol keys derivable, but does not make every
key active.

KeyMaster metadata records:

- which protocols are assigned to an identity;
- algorithm, key role, and key index;
- whether each assignment is active;
- protocol-specific public metadata;
- authorization policy and allowed Avatars.

When creating an identity, the user selects its protocols directly or applies
an identity template. Templates can provide default protocols, algorithms,
roles, indices, metadata requirements, and approval policies. Templates never
contain seeds or private keys.

KeyMaster may persist and synchronize this metadata as signed, encrypted Nostr
events. Relays provide storage and synchronization but are not authorization
authorities. Metadata events must never contain mnemonic phrases, seeds,
private keys, or secret passphrases.

## Protocol-First Design

Design each protocol-specific request-response API first. Do not prematurely
replace them with a generic cryptographic API. After several protocols are
defined, compare them and extract common operations only where the contracts
are genuinely equivalent.

### SSH

The SSH contract is documented in [SSH.md](SSH.md).

Initial KeyMaster operations:

```text
ssh.listIdentities
ssh.sign
```

The SSH Avatar service exposes the standard SSH-agent Unix socket and handles
SSH-agent framing locally.

### PKCS#11

The PKCS#11 contract is documented in [PKCS11.md](PKCS11.md).

Initial service operations:

```text
pkcs11.open
pkcs11.describeToken
pkcs11.listObjects
pkcs11.getObject
pkcs11.login
pkcs11.sign
pkcs11.logout
pkcs11.close
```

A PKCS#11 token is a virtual smart card: a configured view of active PKCS#11
keys belonging to a KeyMaster identity. It is not the seed and does not expose
all derivable keys.

Each client-certificate identity is represented locally by:

```text
CKO_CERTIFICATE
CKO_PUBLIC_KEY
CKO_PRIVATE_KEY reference
```

These objects share `CKA_ID`. The private-key object is non-extractable and
contains only a KeyMaster reference.

The Rust PKCS#11 adapter implements native module, slot, session, object
handle, search, attribute, and multipart mechanics. KeyMaster supplies
authorized metadata and performs signing.

## Earlier Documents

Documents predating the new architecture are preserved under:

```text
/home/rene/git/club.dwdc.keyvault/doc/old
```

They are historical references and do not override the current architecture.

## Likely Next Work

1. Review and refine the PKCS#11 token, slot, login, and certificate model.
2. Define the concrete Nostr envelope shared by Avatar and KeyMaster.
3. Define Nostr event schemas for encrypted identity configuration metadata.
4. Define identity-template and protocol-assignment data models.
5. Implement the SSH contract before extracting any generic service API.

## Resuming

At the beginning of a new session, provide this file as context:

```text
/home/rene/git/club.dwdc.keyvault/doc/PROJECT-CONTEXT.md
```

Then read the linked architecture and protocol documents before making design
or implementation changes.
