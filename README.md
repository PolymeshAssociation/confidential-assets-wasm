# Polymesh DART WASM

WebAssembly bindings for Polymesh DART (Decentralized, Anonymous and Regulation-Friendly Tokenization).

This package provides JavaScript/TypeScript bindings for the Polymesh DART protocol, enabling privacy-preserving asset transfers with zero-knowledge proofs in web browsers and Node.js environments.

This release targets [`polymesh-dart` `dart-v1.0.0`](https://github.com/PolymeshAssociation/polymesh-dart/tree/dart-v1.0.0) and a chain running the DART v1 confidential-assets pallet. See [MIGRATION.md](MIGRATION.md) for the changes from the DART v0.1 release.

## Features

- **Account Management**: Generate and manage DART account keys
- **Zero-Knowledge Proofs**: Generate privacy-preserving proofs for confidential transactions
- **Asset Handling**: Work with asset states and mediators/auditors
- **Settlement Operations**: Create and manage confidential asset settlements
- **TypeScript Support**: Full TypeScript type definitions included
- **Framework Flexible**: Works with or without on-chain integration (use with Polkadot.js, PolymeshClient, or any other chain client)

## Installation

```bash
npm install @polymesh/dart-wasm
```

## Key Concepts

### On-Chain Integration is Optional

This library focuses on **zero-knowledge proof generation** for confidential transactions. You have two options for chain integration:

**Option 1: Use Polkadot.js (Recommended for most developers)**
- Use Polkadot.js to query chain state and submit transactions
- Use `polymesh-dart-wasm` to generate proofs
- This approach is more flexible and requires fewer dependencies
- Perfect if you're already using Polkadot.js in your project

**Option 2: Use PolymeshClient (For testing/development - requires special build)**
- `PolymeshClient` and `PolymeshSigner` provide a convenient wrapper around Polymesh-specific operations
- Best for rapid testing and development
- Requires building with `build_with_rust_client.sh` script
- See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed integration examples

The core proof generation APIs (AccountKeys, AssetState, SettlementBuilder, etc.) work independently and are the primary focus of this library.

### Role Claims

The DART v1 chain only lets an identity create a confidential asset, or be named as its auditor or mediator, if the identity holds the matching claim from a trusted claim issuer. 
The default claims are `KnowYourCustomer(Custom("DART:AssetCreator"))`, `KnowYourCustomer(Custom("DART:Auditor"))` and `KnowYourCustomer(Custom("DART:Mediator"))`. 
Without them, asset creation fails with `MissingRequiredClaim`. Each role's required claim and trusted issuers are stored on chain in `confidentialAssets.requiredClaims(role)`, and Root changes them with `setRequiredClaim` and `removeRequiredClaim`. If `requiredClaims(Mediator)` is unset, mediators are checked against `requiredClaims(Auditor)`, so they need the `DART:Auditor` claim.

The trusted issuer adds the claims with `PolymeshSigner.addConfidentialRoleClaims(did, roles)`, signed with its own key. On the development chain, where Alice is the trusted issuer, `PolymeshClient.onboardConfidentialRoles(signer, roles)` has Alice add them to the signer's identity. On other chains `onboardConfidentialRoles` fails or adds claims the chain ignores.

## Usage

### Browser (ES Modules)

```javascript
import init, { AccountKeys, generateRandomSeed } from '@polymesh/dart-wasm';

// Initialize the WASM module
await init();

// Generate a random seed for account keys
const seed = generateRandomSeed();
console.log('Seed:', seed);

// Create account keys from the seed
const accountKeys = new AccountKeys(seed);

// Get public keys
const publicKeys = accountKeys.publicKeys();
console.log('Public keys:', publicKeys.toJson());
```

### Node.js

```javascript
const { AccountKeys, MasterSeed, generateRandomSeed } = require('@polymesh/dart-wasm');

// Keys from a random 32-byte seed
const seed = generateRandomSeed();
const accountKeys = new AccountKeys(seed);
const publicKeys = accountKeys.publicKeys();

console.log('Account public key:', publicKeys.accountPublicKey().toJson());
console.log('Encryption public key:', publicKeys.encryptionPublicKey().toJson());

// Several accounts from one master seed (at least 32 bytes)
const masterSeed = new MasterSeed('0x' + generateRandomSeed());
const account0 = masterSeed.deriveAccountKeys("m/44'/595'/0'/0/0");
```

### TypeScript

```typescript
import init, { 
  AccountKeys, 
  AccountPublicKeys,
  AssetState,
  generateRandomSeed 
} from '@polymesh/dart-wasm';

await init();

// Generate keys with full type safety
const seed: string = generateRandomSeed();
const keys: AccountKeys = new AccountKeys(seed);
const pubKeys: AccountPublicKeys = keys.publicKeys();
```

## Building from Source

### Prerequisites

- Rust (latest stable) with the `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- wasm-pack (`cargo install wasm-pack`)

On Apple Silicon, if `wasm-pack` fails with `bad CPU type in executable`, the installed binary is an x86_64 build. Reinstall it with `cargo install --force wasm-pack`.

### Build

```bash
# Build for all targets (web, node, bundler)
./build.sh

# Or build for specific target
wasm-pack build --target web
wasm-pack build --target nodejs
wasm-pack build --target bundler
```

The built packages will be in:
- `pkg/` - For bundlers (webpack, rollup, etc.)
- `pkg-web/` - For web browsers (ES modules)
- `pkg-node/` - For Node.js

`./build_with_rust_client.sh` builds the same targets with `PolymeshClient` and `PolymeshSigner`. That build generates its chain API from the metadata of a running node at `POLYMESH_NODE_URL` (default `ws://localhost:9944`), which must run the DART v1 runtime. See [Integration tests](#integration-tests-against-a-local-chain) for starting one.

## Testing

### Browser tests

`tests/wasm_tests.rs` runs in headless Firefox through `wasm-pack test`. It needs Firefox and `geckodriver`:

```bash
cargo install geckodriver
```

```bash
npm test
```

`npm test` runs `wasm-pack test --headless --firefox`. To use Chrome instead, install a `chromedriver` that matches the installed Chrome version and run:

```bash
wasm-pack test --headless --chrome
```

Without `--headless`, `wasm-pack test` serves the tests at a printed URL to open in any browser.

### Integration tests against a local chain

The Node.js examples in `examples/` run full flows (account and asset registration, minting, settlement, affirmations, claims) against a local development chain.

1. Build and start a Polymesh node from the [`confidential_assets_dart-v1.0.0`](https://github.com/PolymeshAssociation/Polymesh/tree/confidential_assets_dart-v1.0.0) branch:

   ```bash
   cargo build --release
   ```

   ```bash
   ./target/release/polymesh --dev --tmp
   ```

2. With the node running, build the package with `PolymeshClient`:

   ```bash
   ./build_with_rust_client.sh
   ```

3. Install the WebSocket dependency the examples load, and run them:

   ```bash
   npm install --no-save ws
   ```

   ```bash
   node examples/node-example.js
   ```

   ```bash
   node examples/node-example-multi-leg.js
   ```

The examples onboard their own identities and role claims, using Alice as the trusted claim issuer. `examples/node-example-keys.js` needs no chain.

## API Documentation

The generated `polymesh_dart_wasm.d.ts` in each built package is the complete reference. This section covers the main types.

### Key Management

#### `generateRandomSeed(): string`
Generates a cryptographically secure random seed (32 bytes, hex-encoded).

#### `AccountKeys`
Represents an account's private keys.

- `new AccountKeys(seedHex: string)` - Create from 64-character hex seed
- `fromSeed(seed: string)` - Create from any string (will be hashed)
- `publicKeys(): AccountPublicKeys` - Get corresponding public keys
- `encryptionKeyPair(): EncryptionKeyPair` - Get the encryption key pair, used to decrypt legs as an auditor or mediator
- `registerAccountProof(did)` - Generate an `AccountRegistrationProof`
- `registerAccountAssetProof(assetId: number, did)` - Generate an `AccountAssetRegistration` (proof and initial `AccountAssetState`)
- `mediatorAffirmationProof(settlementRef, legId, legEnc, accept, assetId, amount)` - Generate a `MediatorAffirmationProof`

`AccountKeys` has no export. Persist the seed and recreate the keys from it.

#### `MasterSeed`
Derives several `AccountKeys` from one seed.

- `new MasterSeed(seed: string)` - Create from a seed of at least 32 bytes (`0x`-prefixed hex, or a string of at least 32 bytes)
- `deriveAccountKeys(path: string): AccountKeys` - Derive keys for a path (e.g. `"m/44'/595'/0'/0/0"`)

#### `AccountPublicKeys`
Represents an account's public keys.

- `new AccountPublicKeys(keys)` - Create from bytes, hex or a JS object
- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `accountPublicKey(): AccountPublicKey` - Get account's affirmation public key
- `encryptionPublicKey(): EncryptionPublicKey` - Get encryption public key

### Account State

#### `AccountAssetState`
Represents the confidential state of an account for a specific asset.

- `fromBytes(bytes: Uint8Array)` - Import from SCALE-encoded bytes
- `toBytes(): Uint8Array` - Export as SCALE-encoded bytes
- `assetId(): number` - Get the asset ID
- `balance()` - Get current balance
- `leafIndex(): bigint` - Get the leaf index in the account tree (after committing)
- `hasPendingState(): boolean` - Whether a generated proof's state change is not yet committed
- `commitPendingState(leafIndex: bigint)` - Commit pending state after on-chain transaction
- `assetMintingProof`, `senderAffirmProof`, `receiverAffirmProof`, `receiverClaimProof`, `senderCounterUpdateProof`, `senderRevertProof` - Generate the proofs that update this state

#### `AccountState`
Represents account commitment stored in the account tree.

- `fromBytes(bytes: Uint8Array)` - Import from SCALE-encoded bytes
- `toBytes(): Uint8Array` - Export as SCALE-encoded bytes
- `assetId(): number` - Get asset ID
- `balance()` - Get balance
- `counter(): bigint` - Get transaction counter

### Asset Management

#### `AssetState`
Represents a confidential asset's state, including mediators and auditors.

- `new AssetState(assetId: number, keys)` - Create from the chain's `confidentialAssets.keys(assetId)` value
  - `keys` is the SCALE bytes of that value (`Uint8Array` or hex string), or an object `{ encKeys: [...], mediators: [...] }` of hex strings or bytes, where `encKeys` are the auditor and mediator encryption public keys and `mediators` are the mediators' account public keys
  - `isFrozen()` is `false`. Use `PolymeshClient.getAssetState(assetId)` to also read the frozen status
- `fromBytes(bytes: Uint8Array)` - Import from SCALE-encoded bytes
- `toBytes(): Uint8Array` - Export as SCALE-encoded bytes
- `assetId(): number` - Get asset ID
- `isFrozen(): boolean` - Whether the asset is frozen. The chain rejects new settlements for a frozen asset
- `mediatorCount(): number` - Get number of mediators
- `auditorCount(): number` - Get number of encryption keys (auditors and mediators)

### Settlement Operations

#### `SettlementBuilder`
Builds a confidential settlement with multiple transfer legs.

- `new SettlementBuilder(memo: string|Uint8Array, blockNumber: number, assetTreeRoot: AssetTreeRoot)` - Create builder
- `addLeg(leg: LegBuilder)` - Add a transfer leg
- `addAssetPath(assetId: number, path: AssetLeafPath)` - Add asset curve tree path (once per asset)
- `build(): SettlementProof` - Generate the settlement proof

#### `LegBuilder`
Represents a single transfer leg in a settlement.

- `new LegBuilder(sender: AccountPublicKeys, receiver: AccountPublicKeys, assetState: AssetState, amount: bigint)` - Create leg
- Handles encryption of transfer details for mediators and auditors

#### `SettlementProof`
The zero-knowledge proof for a settlement.

- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `getEncryptedLegs(): SettlementLegsEncrypted` - Get the encrypted legs
- `getLegCount(): number`, `getMemo()`, `getBlockNumber(): number`

#### `SettlementLegEncrypted` / `SettlementLegsEncrypted`
An encrypted settlement leg, and all encrypted legs of a settlement.

- `tryDecrypt(keys: AccountKeys)` - Decrypt as the sender or receiver
- `SettlementLegEncrypted.tryDecryptAsMediatorOrAuditor(encryptionKey: EncryptionKeyPair, maxAssetId?, affirmationKey?, maxAmount?)` - Decrypt as an auditor or mediator
- `SettlementLegsEncrypted.tryDecryptAsMediatorOrAuditor(encryptionKey: EncryptionKeyPair, affirmationKey?, maxAmount?)` - Same, for all legs

Without `affirmationKey`, the decrypted role is `Auditor`. A mediator passes its account public key (`AccountPublicKey`, hex string or `Uint8Array`) to be identified as `Mediator`:

```javascript
const legs = settlementLegs.tryDecryptAsMediatorOrAuditor(
  mediatorKeys.encryptionKeyPair(),
  mediatorKeys.publicKeys().accountPublicKey(),
);
```

#### Proof Types

All proof types support:
- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes

All except `AccountRegistrationProof` also support:
- `fromHex(hex: string)` - Import from hex
- `toHex(): string` - Export as hex

Available proofs:
- `AccountRegistrationProof` - Register account keys on-chain
- `AccountAssetRegistrationProof` - Register account for a specific asset
- `AssetMintingProof` - Mint tokens of a confidential asset
- `SenderAffirmationProof` - Sender affirmation for a settlement leg
- `ReceiverAffirmationProof` - Receiver affirmation for a settlement leg
- `ReceiverClaimProof` - Claim received tokens
- `SenderCounterUpdateProof` - Update sender's counter after transaction
- `SenderRevertAffirmationProof` - Reverse a failed settlement
- `MediatorAffirmationProof` - Mediator affirmation for a settlement
- `SettlementProof` - Complete settlement with multiple legs

## Examples

See the `examples/` directory for complete working examples:
- `basic-keys.html` - Key generation and management in the browser
- `node-example-keys.js` - Key generation, asset state and registration proofs, no chain needed
- `node-example.js` - Single-leg settlement with PolymeshClient
- `node-example-multi-leg.js` - Multi-leg settlement with PolymeshClient
- `node-example-account-leaf-path-and-root.js`, `node-example-asset-leaf-path-and-root.js` - Curve tree leaf paths

## Using with Polkadot.js (Without PolymeshClient)

For most production use cases, you'll want to use Polkadot.js for chain queries and transactions. Here's how to integrate:

```javascript
import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { 
  AccountKeys, 
  AssetState, 
  generateRandomSeed 
} from '@polymesh/dart-wasm';

// Connect to chain using Polkadot.js
const provider = new WsProvider('ws://localhost:9944');
const api = await ApiPromise.create({ provider });
const signer = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');

// Generate DART keys for confidential transactions
const dartKeys = new AccountKeys(generateRandomSeed());
const publicKeys = dartKeys.publicKeys();

// Query asset state from chain
const assetId = 1;
const assetKeys = await api.query.confidentialAssets.keys(assetId);
const assetState = new AssetState(assetId, assetKeys.unwrap().toU8a());

// Generate proof for registration
const accountDid = '0x1234...'; // Your account DID
const registration = dartKeys.registerAccountAssetProof(assetId, accountDid);

// Submit transaction using Polkadot.js
const extrinsic = api.tx.confidentialAssets.registerAccountAssets(
  registration.getBatchedProofBytes()
);
const hash = await extrinsic.signAndSend(signer);
console.log('Transaction hash:', hash);
```

## License

GPL-3.0

## Links

- [Polymesh Website](https://polymesh.network)
- [GitHub Repository](https://github.com/PolymeshAssociation/polymesh-dart)
- [P-DART Paper](https://assets.polymesh.network/P-DART-v1.pdf)
