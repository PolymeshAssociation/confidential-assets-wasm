# Polymesh DART WASM

WebAssembly bindings for Polymesh DART (Decentralized, Anonymous and Regulation-Friendly Tokenization).

This package provides JavaScript/TypeScript bindings for the Polymesh DART protocol, enabling privacy-preserving asset transfers with zero-knowledge proofs in web browsers and Node.js environments.

## Features

- **Account Management**: Generate and manage DART account keys
- **Asset Operations**: Register accounts with assets, mint tokens
- **Settlement**: Create and manage confidential asset settlements
- **Zero-Knowledge Proofs**: Generate and verify privacy-preserving proofs
- **TypeScript Support**: Full TypeScript type definitions included

## Installation

```bash
npm install @polymesh/dart-wasm
```

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
Represents the state of an account for a specific asset.

- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `assetId(): number` - Get asset ID
- `balance(): number` - Get current balance

#### `AccountState`
Represents account commitment stored in the account tree.

- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `assetId(): number` - Get asset ID
- `balance(): number` - Get balance
- `counter(): number` - Get transaction counter

### Asset Management

#### `AssetState`
Represents an asset's state in the asset tree.

- `new AssetState(assetId: number, mediators: Uint8Array[], auditors: Uint8Array[])` - Create new asset state
- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `assetId(): number` - Get asset ID
- `mediatorCount(): number` - Get number of mediators
- `auditorCount(): number` - Get number of auditors

### Settlement Operations

#### `Leg`
Represents a settlement leg (asset transfer).

- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `assetId(): number` - Get asset ID
- `amount(): number` - Get transfer amount

#### `LegEncrypted`
Encrypted settlement leg.

- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `fromHex(hex: string)` - Import from hex string
- `toHex(): string` - Export as hex string

#### Proof Types

All proof types support:
- `fromBytes(bytes: Uint8Array)` - Import from bytes
- `toBytes(): Uint8Array` - Export as bytes
- `fromHex(hex: string)` - Import from hex
- `toHex(): string` - Export as hex

Proof types:
- `AccountAssetRegistrationProof`
- `AssetMintingProof`
- `SenderAffirmationProof`
- `ReceiverAffirmationProof`
- `ReceiverClaimProof`
- `SenderCounterUpdateProof`
- `SenderReversalProof`
- `MediatorAffirmationProof`

## Examples

See the `examples/` directory for complete working examples:
- `basic-keys.html` - Key generation and management
- `node-example.js` - Node.js usage example

## License

GPL-3.0

## Links

- [Polymesh Website](https://polymesh.network)
- [GitHub Repository](https://github.com/PolymeshAssociation/polymesh-dart)
- [P-DART Paper](https://assets.polymesh.network/P-DART-v1.pdf)
