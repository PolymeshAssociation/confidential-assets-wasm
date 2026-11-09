# Migrating to DART v1.0.0

This release moves `@polymesh/dart-wasm` from the DART v0.1 code (`polymesh-dart` `main` at `90d4e67`) to [`polymesh-dart` `dart-v1.0.0`](https://github.com/PolymeshAssociation/polymesh-dart/tree/dart-v1.0.0). It targets a chain running the confidential-assets pallet from the Polymesh branch [`confidential_assets_dart-v1.0.0`](https://github.com/PolymeshAssociation/Polymesh/tree/confidential_assets_dart-v1.0.0) (spec `8002000`).

Legend for the `Kind` column: `Breaking` = existing calls or stored data fail, or produce results incompatible with v0.1. `Behavior` = same call succeeds with a different result. `Additive` = new, existing calls unaffected. `None` = no consumer change.

## Chain compatibility

Proofs and encrypted legs produced by this release verify only on a DART v1 chain, and v0.1 proofs do not verify on it. Pending v0.1 settlements are rejected by the chain's storage migration and their legs cannot be affirmed, so settle or cancel them before the upgrade.

The v1 pallet gates three roles behind an identity claim from a trusted issuer. The default per-role claim is `KnowYourCustomer(Custom("DART:AssetCreator" | "DART:Auditor" | "DART:Mediator"))`, stored in `confidentialAssets.requiredClaims(role)` together with its trusted issuers, and Root can change it with `confidentialAssets.setRequiredClaim`. If `requiredClaims(Mediator)` is unset, mediators are checked against `requiredClaims(Auditor)`. `createAsset` fails with `MissingRequiredClaim` when the issuer, an auditor or a mediator lacks the claim. The trusted issuer adds the claims with `PolymeshSigner.addConfidentialRoleClaims(did, roles)`. On a development chain, where Alice is the genesis trusted issuer, `PolymeshClient.onboardConfidentialRoles(signer, roles)` adds them.

## JavaScript API changes

| API | Kind | Change | Action |
|---|---|---|---|
| `MasterSeed.deriveAccountKeys(path)` | Breaking | Derivation uses HKDF. The same seed and path give different keys than v0.1. | v1 cannot re-derive keys a `MasterSeed` produced under v0.1, and `AccountKeys` has no export. Before the chain upgrade, move balances out of `MasterSeed`-derived accounts. After it, register the v1-derived keys. |
| `new MasterSeed(seed)` | Breaking | Throws if the seed is shorter than 32 bytes or a `0x` string is not valid hex. v0.1 accepted any length and fell back to raw bytes on bad hex. | Use a seed of at least 32 bytes, e.g. `new MasterSeed("0x" + generateRandomSeed())`. |
| `AccountKeys.fromSeed(seed)` | None | Derives the same keys as v0.1. | None. |
| `SettlementLegEncrypted.tryDecryptAsMediatorOrAuditor(encryptionKey, maxAssetId?, affirmationKey?, maxAmount?)` | Behavior, Additive | v1 encrypts every mediator entry to every asset encryption key, so an encryption key alone no longer identifies a mediator. Without `affirmationKey` the returned role is always `Auditor`. New optional `affirmationKey` (`AccountPublicKey`, hex string or `Uint8Array`) and `maxAmount` (`bigint` or number). | Mediators pass their account public key: `leg.tryDecryptAsMediatorOrAuditor(encKeys, null, keys.publicKeys().accountPublicKey())`. |
| `SettlementLegsEncrypted.tryDecryptAsMediatorOrAuditor(encryptionKey, affirmationKey?, maxAmount?)` | Behavior, Additive | Same as above. Now throws if `maxAmount` is invalid. | Same as above. |
| `AssetState.fromBytes` / `toBytes` | Breaking | The encoding gains a `frozen` field. Bytes saved by v0.1 fail to decode. | Rebuild the asset state from the chain (`PolymeshClient.getAssetState` or `new AssetState(assetId, keys)`). |
| `new AssetState(assetId, keys)` | Breaking | `keys` must be the v1 `confidentialAssets.keys` storage value: `{ enc_keys: [EncryptionPublicKey...], mediators: [AccountPublicKey...] }`. The v0.1 shape mapped each mediator to an encryption-key index. `enc_keys` is the chain's field name. The JS object form also accepts `encKeys`. `frozen` is set to `false`. | Pass the chain's v1 `Keys` value. Use `PolymeshClient.getAssetState` to also get the frozen status. |
| `AssetState.isFrozen()` | Additive | Returns the asset's frozen status. The chain rejects new settlements for a frozen asset. | None. |
| `PolymeshClient.getAssetState(assetId)` | Behavior | Also reads `confidentialAssets.assetFrozen` and sets `frozen`. | None. |
| `PolymeshClient.onboardConfidentialRoles(signer, roles)` | Additive | Development chains only. Alice adds the default DART role claims (`"AssetCreator"`, `"Auditor"`, `"Mediator"`) to the signer's identity. | Call after `onboardSigner` for asset issuers, auditors and mediators. |
| `PolymeshSigner.addConfidentialRoleClaims(did, roles)` | Additive | The signer's identity adds the default DART role claims to `did`. The claims count only if the signer's identity is a trusted issuer for the role. | The trusted issuer calls it for asset issuers, auditors and mediators. |
| `AccountKeys.mediatorAffirmationProof(...)` | None | Signature unchanged. Mediator role is found with the account's affirmation key. | None. |
| `AccountAssetState.receiverAffirmProof`, `senderCounterUpdateProof` | None | Signatures unchanged. The proof now binds the leg amount, taken from the decrypted leg. | None. |
| `AccountKeys.registerAccountAssetProof(assetId, did)` | None | Signature unchanged. Registers without an issuer force-transfer key, matching the chain. | None. |
| `PolymeshSigner.createAsset(name, symbol, decimals, mediators, auditors, data)` | None | Signature unchanged. `CreateAssetResult.assetState()` has `frozen = false`. | None. |
| All proof types, `SettlementLegEncrypted`, `SettlementLegsEncrypted` | Breaking | Wire formats changed. | Regenerate. Do not reuse v0.1 bytes. |

## Persisted data

| Type | v0.1 bytes decode in v1 |
|---|---|
| `AccountAssetState` | Yes. Encoding unchanged. |
| `AssetState` | No. Rebuild from chain. |
| Proofs, encrypted legs | No. Regenerate. |

## Building from source

`Cargo.toml` points every Polymesh git dependency (`polymesh-dart`, `curve-trees`, `crypto`, `arkworks-algebra`) at the `dart-v1.0.0` branch and depends on `polymesh-dart` `1.0.0`. Changes:

- The `host_proofs` feature of `polymesh-dart` is enabled. v1 gates proof generation and the `curve_tree` module behind it.
- New `[patch.crates-io]` entries: `ark-host-hash-to-curve`, `ark-host-hash-to-curve-impl`, `ark-secp256k1`, `ark-secq256k1`.
- The `polymesh-client` feature generates its chain API from a node's metadata (`POLYMESH_NODE_URL`, default `ws://localhost:9944`). That node must run the DART v1 runtime.
