# Polymesh DART WASM

WebAssembly bindings for Polymesh DART (Decentralized, Anonymous and Regulation-Friendly Tokenization).

This package provides JavaScript/TypeScript bindings for the Polymesh DART protocol, enabling privacy-preserving asset transfers with zero-knowledge proofs in web browsers and Node.js environments.

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

// Export keys as bytes
const keyBytes = accountKeys.toBytes();
console.log('Key bytes length:', keyBytes.length);
```

### Node.js

```javascript
const { AccountKeys, generateRandomSeed } = require('@polymesh/dart-wasm');

// Generate account keys
const seed = generateRandomSeed();
const accountKeys = AccountKeys.fromSeed("my-secret-seed");
const publicKeys = accountKeys.publicKeys();

console.log('Account public key:', publicKeys.accountPublicKey().toJson());
console.log('Encryption public key:', publicKeys.encryptionPublicKey().toJson());
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

- Rust (latest stable)
- wasm-pack (`cargo install wasm-pack`)

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

## API Documentation

### Key Management

#### `generateRandomSeed(): string`
Generates a cryptographically secure random seed (32 bytes, hex-encoded).

#### `AccountKeys`
Represents an account's private keys.

- `new AccountKeys(seedHex: string)` - Create from 64-character hex seed
- `fromSeed(seed: string)` - Create from any string (will be hashed)
- `fromBytes(bytes: Uint8Array)` - Import from SCALE-encoded bytes
- `toBytes(): Uint8Array` - Export as SCALE-encoded bytes
- `publicKeys(): AccountPublicKeys` - Get corresponding public keys

#### `AccountPublicKeys`
Represents an account's public keys.

- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `accountPublicKey(): AccountPublicKey` - Get account public key
- `encryptionPublicKey(): EncryptionPublicKey` - Get encryption public key

### Account State

#### `AccountAssetState`
Represents the confidential state of an account for a specific asset.

- `fromBytes(bytes: Uint8Array)` - Import from SCALE-encoded bytes
- `toBytes(): Uint8Array` - Export as SCALE-encoded bytes
- `assetId(): number` - Get the asset ID
- `balance(): number` - Get current balance
- `leafIndex(): number` - Get the leaf index in the account tree (after committing)
- `commitPendingState(leafIndex: number)` - Commit pending state after on-chain transaction
- `getProof(): Uint8Array` - Get current proof state

#### `AccountState`
Represents account commitment stored in the account tree.

- `fromBytes(bytes: Uint8Array)` - Import from SCALE-encoded bytes
- `toBytes(): Uint8Array` - Export as SCALE-encoded bytes
- `assetId(): number` - Get asset ID
- `balance(): number` - Get balance
- `counter(): number` - Get transaction counter

### Asset Management

#### `AssetState`
Represents a confidential asset's state, including mediators and auditors.

- `new AssetState(assetId: number, mediators: Array, auditors: Array)` - Create new asset state
  - Automatically converts chain data (Uint8Array, hex strings, or EncryptionPublicKey objects)
  - Perfect for data from Polkadot.js queries
- `fromBytes(bytes: Uint8Array)` - Import from SCALE-encoded bytes
- `toBytes(): Uint8Array` - Export as SCALE-encoded bytes
- `assetId(): number` - Get asset ID
- `mediatorCount(): number` - Get number of mediators
- `auditorCount(): number` - Get number of auditors

### Settlement Operations

#### `SettlementBuilder`
Builds a confidential settlement with multiple transfer legs.

- `new SettlementBuilder(memo: string|Uint8Array, blockNumber: number, assetTreeRoot: AssetTreeRoot)` - Create builder
- `addLeg(leg: LegBuilder)` - Add a transfer leg
- `addAssetPath(assetId: number, path: AssetLeafPath)` - Add asset curve tree path (once per asset)
- `build(): SettlementProof` - Generate the settlement proof

#### `LegBuilder`
Represents a single transfer leg in a settlement.

- `new LegBuilder(senderKeys: AccountKeys, receiverKeys: AccountPublicKeys, assetState: AssetState, amount: BigInt)` - Create leg
- Handles encryption of transfer details for mediators and auditors

#### `SettlementProof`
The zero-knowledge proof for a settlement.

- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `fromHex(hex: string)` - Import from hex string
- `toHex(): string` - Export as hex string

#### Proof Types

All proof types support serialization:

All proof types support:
- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
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
- `SenderReversalProof` - Reverse a failed settlement
- `MediatorAffirmationProof` - Mediator affirmation for a settlement
- `SettlementProof` - Complete settlement with multiple legs

## Examples

See the `examples/` directory for complete working examples:
- `basic-keys.html` - Key generation and management
- `node-example.js` - Node.js usage with PolymeshClient

## Using with Polkadot.js (Without PolymeshClient)

For most production use cases, you'll want to use Polkadot.js for chain queries and transactions. Here's how to integrate:

```javascript
import { ApiPromise, WsProvider } from '@polkadot/api';
import { 
  AccountKeys, 
  AssetState, 
  SettlementBuilder,
  LegBuilder,
  generateRandomSeed 
} from '@polymesh/dart-wasm';

// Connect to chain using Polkadot.js
const provider = new WsProvider('ws://localhost:9944');
const api = await ApiPromise.create({ provider });

// Generate DART keys for confidential transactions
const dartKeys = new AccountKeys(generateRandomSeed());
const publicKeys = dartKeys.publicKeys();

// Query asset state from chain
const assetId = 1;
const assetDetails = await api.query.confidentialAssets.dartAssetDetails(assetId);
const assetState = new AssetState(
  assetId,
  assetDetails.mediators,  // Automatically converted from chain format
  assetDetails.auditors
);

// Generate proof for registration
const accountDid = '0x1234...'; // Your account DID
const proof = dartKeys.registerAccountAssetProof(assetId, accountDid);

// Submit transaction using Polkadot.js
const extrinsic = api.tx.confidentialAssets.registerAccountAsset(
  proof.getProof().toBytes()
);
const hash = await extrinsic.signAndSend(keyring.getPair(signer));
console.log('Transaction hash:', hash);
```

## License

GPL-3.0

## Links

- [Polymesh Website](https://polymesh.network)
- [GitHub Repository](https://github.com/PolymeshAssociation/polymesh-dart)
- [P-DART Paper](https://assets.polymesh.network/P-DART-v1.pdf)
