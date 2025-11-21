# Polymesh DART WASM Development Guide

This guide provides detailed information for developers working with the Polymesh DART WASM bindings.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Key Concepts](#key-concepts)
3. [Building the WASM Package](#building-the-wasm-package)
4. [Integration Guide](#integration-guide)
5. [API Reference](#api-reference)
6. [Performance Considerations](#performance-considerations)
7. [Troubleshooting](#troubleshooting)

## Architecture Overview

The `polymesh-dart-wasm` package provides WebAssembly bindings for the Polymesh DART protocol. It wraps the core Rust implementation with JavaScript/TypeScript-friendly APIs using `wasm-bindgen`.

### Key Components

```
polymesh-dart-wasm/
├── src/
│   ├── lib.rs           # Main entry point and module exports
│   ├── utils.rs         # Utility functions and error handling
│   ├── keys.rs          # Account and encryption key management
│   ├── account.rs       # Account state and proofs
│   ├── asset.rs         # Asset state management
│   ├── settlement.rs    # Settlement operations and proofs
│   ├── curve_tree.rs    # Curve tree operations
│   ├── client.rs        # Optional PolymeshClient integration
│   └── error.rs         # Error types
├── examples/            # Example HTML and Node.js applications
├── tests/               # WASM-specific tests
├── Cargo.toml          # Rust dependencies and configuration
├── package.json        # NPM package metadata
└── build.sh            # Build script for all targets
```

### Data Flow

1. **Key Generation**: JavaScript → WASM → Rust crypto primitives → WASM → JavaScript
2. **Proof Generation**: Keys + State → WASM → Zero-knowledge proof → WASM → Serialized proof
3. **Proof Verification**: Serialized proof → WASM → Verification → Boolean result

## Key Concepts

### Chain Integration is Optional

This library is designed to work with **any** chain client:

- **Polkadot.js** (Recommended): Lightweight, flexible, industry standard
- **PolymeshClient** (Optional): Convenience wrappers for Polymesh-specific operations (requires separate build)
- **Your custom client**: Use any solution that fits your architecture

The core proof generation and account/asset management APIs work independently.

### PolymeshClient Feature (Optional)

The `PolymeshClient` and signers are NOT included by default. They are provided as an optional feature for testing and development purposes.

**Default build** (use this for production):
```bash
./build.sh
```
This creates minimal, optimized WASM bindings with only proof generation APIs.

**Build with PolymeshClient** (for testing/development with Polymesh-specific convenience methods):
```bash
./build_with_rust_client.sh
```
This includes `PolymeshClient`, `PolymeshSigner`, and related APIs.

The feature flag in `Cargo.toml`:
```toml
[features]
default = []  # Empty - no PolymeshClient by default
polymesh-client = ["polymesh-api-client", "polymesh-api", ...]
```

**Key differences:**

| Feature | Default Build | With `build_with_rust_client.sh` |
|---------|---------------|----------------------------------|
| AccountKeys, AssetState, proofs | ✓ | ✓ |
| PolymeshClient | ✗ | ✓ |
| PolymeshSigner | ✗ | ✓ |
| Bundle size | ~1 MB | ~3 MB |
| Use case | Production | Testing/Development |
| Dependencies | Minimal | Polymesh chain types |

You only need PolymeshClient if you want to use the convenience wrapper for Polymesh operations. For most use cases with Polkadot.js, use the default build.

## Building the WASM Package

### Prerequisites

Install the required tools:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install wasm-pack
cargo install wasm-pack

# Add wasm32 target
rustup target add wasm32-unknown-unknown
```

### Build Commands

#### Build for all targets (recommended)

```bash
cd polymesh-dart-wasm
./build.sh
```

This creates three output directories:
- `pkg/` - For bundlers (webpack, rollup, parcel, etc.)
- `pkg-web/` - For direct browser use with ES modules
- `pkg-node/` - For Node.js applications

#### Build for specific targets

```bash
# For bundlers (webpack, rollup, etc.)
wasm-pack build --target bundler --out-dir pkg

# For web browsers (ES modules)
wasm-pack build --target web --out-dir pkg-web

# For Node.js
wasm-pack build --target nodejs --out-dir pkg-node
```

#### Development build with debug symbols

```bash
wasm-pack build --dev --target web
```

#### Production build (optimized)

```bash
wasm-pack build --release --target bundler
```

### Build Options

The `Cargo.toml` includes optimizations for WASM:

```toml
[profile.release]
opt-level = "s"  # Optimize for size
lto = true       # Enable link-time optimization
```

For even smaller builds, you can use `opt-level = "z"` and enable `wasm-opt`:

```bash
wasm-pack build --target web -- -Z build-std=std,panic_abort
```

## Integration Guide

### Option 1: Using Polkadot.js (Recommended)

This is the recommended approach for production applications. You use Polkadot.js for all chain interactions while using `polymesh-dart-wasm` for proof generation. This works with the default build from `./build.sh`.

```typescript
import { ApiPromise, WsProvider } from '@polkadot/api';
import { 
  AccountKeys, 
  AssetState, 
  SettlementBuilder,
  LegBuilder,
  generateRandomSeed 
} from '@polymesh/dart-wasm';
import { Keyring } from '@polkadot/keyring';

async function main() {
  // 1. Connect to chain using Polkadot.js
  const provider = new WsProvider('ws://localhost:9944');
  const api = await ApiPromise.create({ provider });

  // 2. Generate or load DART keys (independent of chain)
  const dartSeed = generateRandomSeed();
  const dartKeys = new AccountKeys(dartSeed);
  const publicKeys = dartKeys.publicKeys();

  // 3. Query asset state from chain
  const assetId = 1;
  const assetDetails = await api.query.confidentialAssets.dartAssetDetails(assetId);
  const assetState = new AssetState(
    assetId,
    assetDetails.mediators,      // Automatically converted from chain format
    assetDetails.auditors
  );

  // 4. Generate proof (pure computation, no chain needed)
  const accountDid = '0x1234...'; // Your account DID
  const registration = dartKeys.registerAccountAssetProof(assetId, accountDid);
  const proof = registration.getProof();

  // 5. Submit using Polkadot.js
  const keyring = new Keyring({ type: 'sr25519' });
  const pair = keyring.addFromUri('//Alice');
  
  const extrinsic = api.tx.confidentialAssets.registerAccountAsset(
    proof.toBytes()
  );
  
  const hash = await extrinsic.signAndSend(pair);
  console.log('Transaction hash:', hash);

  // 6. Track account state after transaction
  const accountState = registration.getAccountAssetState();
  // ... later after transaction is finalized
  // accountState.commitPendingState(newLeafIndex);
}

main().catch(console.error);
```

**Advantages:**
- Minimal dependencies
- Works with any Polkadot-compatible chain
- Maximum flexibility
- Production-ready
- Largest ecosystem of tools and libraries
- Smallest bundle size

### Option 2: Using PolymeshClient (For Testing/Development)

The `PolymeshClient` provides convenient wrappers for Polymesh-specific operations. It's best used for rapid testing and development.

**⚠️ Important:** PolymeshClient is NOT included in the default build. You must build with the special script:

```bash
./build_with_rust_client.sh
```

After building, you can use PolymeshClient and PolymeshSigner:

```typescript
import { 
  PolymeshClient, 
  AccountKeys, 
  AssetState,
  generateRandomSeed 
} from '@polymesh/dart-wasm';

async function main() {
  // 1. Connect to Polymesh node
  const client = await PolymeshClient.connect("ws://localhost:9944");
  client.finalize = true; // Wait for finalization (or false for faster testing)

  // 2. Create a signer for submitting transactions
  const issuer = client.newSigner("//TestIssuer");
  const issuerDid = await issuer.identity();
  
  if (!issuerDid) {
    // Onboard new account
    await client.onboardSigner(issuer);
  }

  // 3. Generate DART keys
  const dartKeys = new AccountKeys(generateRandomSeed());

  // 4. Register account
  const accountProof = dartKeys.registerAccountProof(issuerDid);
  await issuer.registerAccount(accountProof);

  // 5. Create asset and register account for asset
  const assetId = await issuer.createAsset("TestAsset");
  const registration = dartKeys.registerAccountAssetProof(assetId, issuerDid);
  
  const leafIndex = await issuer.registerAccountAsset(registration.getProof());

  // 6. Track state
  const accountState = registration.getAccountAssetState();
  accountState.commitPendingState(leafIndex);
}

main().catch(console.error);
```

**Requirements:**
- Build with: `./build_with_rust_client.sh`
- Only available in that special build
- Larger bundle size than default build

**Advantages:**
- Quick development and testing
- Convenience methods for common operations
- Handles Polymesh-specific details automatically

**Disadvantages:**
- Larger bundle size
- Tied to Polymesh chain specifics
- Not suitable for production browser apps

### Webpack Configuration

If you encounter issues with WASM loading, update your webpack config:

```javascript
// webpack.config.js
module.exports = {
  experiments: {
    asyncWebAssembly: true,
  },
  // ... other config
};
```

### Vite Configuration

For Vite projects:

```javascript
// vite.config.js
export default {
  optimizeDeps: {
    exclude: ['@polymesh/dart-wasm']
  }
}
```

### React Application Example

```typescript
import React, { useEffect, useState } from 'react';
import { AccountKeys, generateRandomSeed } from '@polymesh/dart-wasm';

function DartKeyManager() {
  const [accountKeys, setAccountKeys] = useState<AccountKeys | null>(null);

  const generateKeys = () => {
    const seed = generateRandomSeed();
    const keys = new AccountKeys(seed);
    setAccountKeys(keys);
  };

  return (
    <div>
      <button onClick={generateKeys}>Generate Keys</button>
      
      {accountKeys && (
        <pre>{JSON.stringify({
          account: accountKeys.publicKeys().accountPublicKey().toJson(),
          encryption: accountKeys.publicKeys().encryptionPublicKey().toJson()
        }, null, 2)}</pre>
      )}
    </div>
  );
}

export default DartKeyManager;
```

### Vue.js Application Example

```typescript
<template>
  <div>
    <button @click="generateKeys">Generate Keys</button>
    <pre v-if="publicKeys">{{ publicKeys }}</pre>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { AccountKeys, generateRandomSeed } from '@polymesh/dart-wasm';

const publicKeys = ref<string | null>(null);

const generateKeys = () => {
  const seed = generateRandomSeed();
  const keys = new AccountKeys(seed);
  publicKeys.value = JSON.stringify({
    account: keys.publicKeys().accountPublicKey().toJson(),
    encryption: keys.publicKeys().encryptionPublicKey().toJson()
  }, null, 2);
};
</script>
```

### Next.js Application Example

```typescript
// pages/dart-keys.tsx
import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';

const DartKeyManager = dynamic(() => import('../components/DartKeyManager'), {
  ssr: false,
});

export default function DartKeysPage() {
  return (
    <div>
      <h1>DART Key Management</h1>
      <DartKeyManager />
    </div>
  );
}

// components/DartKeyManager.tsx
import { useEffect, useState } from 'react';
import { AccountKeys, generateRandomSeed } from '@polymesh/dart-wasm';

export default function DartKeyManager() {
  const [keys, setKeys] = useState<AccountKeys | null>(null);

  const generateKeys = () => {
    const seed = generateRandomSeed();
    const newKeys = new AccountKeys(seed);
    setKeys(newKeys);
  };

  return (
    <div>
      <button onClick={generateKeys}>Generate Keys</button>
      {keys && (
        <pre>{JSON.stringify({
          account: keys.publicKeys().accountPublicKey().toJson(),
          encryption: keys.publicKeys().encryptionPublicKey().toJson()
        }, null, 2)}</pre>
      )}
    </div>
  );
}
```

## API Reference

### Type Conversions

All WASM types provide serialization methods for flexibility:

```typescript
// SCALE encoding (compact binary format - most efficient)
const bytes: Uint8Array = accountKeys.toBytes();
const restoredKeys = AccountKeys.fromBytes(bytes);

// Hex encoding (for display/storage/transmission)
const hex: string = proof.toHex();
const restoredProof = SenderAffirmationProof.fromHex(hex);

// JSON (for debugging - not all types support this)
const pubKeys = accountKeys.publicKeys();
const json: string = pubKeys.accountPublicKey().toJson();
```

### Error Handling

All WASM functions that can fail return a `Result<T, JsValue>` or throw errors:

```typescript
// Try-catch for synchronous operations
try {
  const keys = new AccountKeys(invalidSeed);
} catch (error) {
  console.error('Failed to create keys:', error);
}

// Async/await for async operations
try {
  await PolymeshClient.connect(url);
} catch (error) {
  console.error('Connection failed:', error);
}
```

### Memory Management

WASM objects are automatically garbage collected by JavaScript. For most use cases, no manual cleanup is needed. For very large objects or tight loops, JavaScript's GC will handle cleanup automatically.

```typescript
// Create and use keys
const keys = new AccountKeys(seed);
const pubKeys = keys.publicKeys();

// Use pubKeys...

// When keys and pubKeys go out of scope, JS GC will clean them up
```

## Performance Considerations

### Initialization

The WASM module loads asynchronously. Initialize once at app startup:

```typescript
// Good: Initialize once at app startup
let wasmInitialized = false;

async function ensureWasmReady() {
  if (!wasmInitialized) {
    await init();
    wasmInitialized = true;
  }
}

// Use in your app
await ensureWasmReady();
const keys = new AccountKeys(seed);
```

### Batch Operations

When performing multiple operations, minimize JavaScript ↔ WASM boundary crossings:

```typescript
// Good: All computation happens in WASM
const proofs = [];
for (let i = 0; i < 100; i++) {
  const keys = AccountKeys.fromSeed(`seed-${i}`);
  const proof = keys.registerAccountProof(didArray[i]);
  proofs.push(proof.toBytes());
}

// Less efficient: Multiple boundary crossings per iteration
for (let i = 0; i < 100; i++) {
  const keys = AccountKeys.fromSeed(`seed-${i}`);
  const pubKeys = keys.publicKeys();
  const acctKey = pubKeys.accountPublicKey();
  const encKey = pubKeys.encryptionPublicKey();
  // Multiple operations spread across boundaries
}
```

### Proof Generation Performance

Proof generation is CPU-intensive (can take seconds for complex proofs). Strategies:

1. **Web Workers**: Offload to background thread (browser/Node.js)
2. **Progress Updates**: Long operations should provide user feedback
3. **Caching**: Cache proofs when possible
4. **Batching**: Generate multiple proofs together when feasible

#### Example with Web Worker

```typescript
// worker.ts
import init, { 
  AccountKeys, 
  SettlementBuilder 
} from '@polymesh/dart-wasm';

let wasmReady = false;

self.onmessage = async (e) => {
  if (!wasmReady) {
    await init();
    wasmReady = true;
  }

  const { type, data } = e.data;

  if (type === 'generateProof') {
    const keys = new AccountKeys(data.seed);
    const proof = keys.registerAccountProof(data.did);
    self.postMessage({ proof: proof.toBytes() });
  }
};

// main.ts
const worker = new Worker(new URL('./worker.ts', import.meta.url));

function generateProofInWorker(seed: string, did: string): Promise<Uint8Array> {
  return new Promise((resolve) => {
    worker.onmessage = (e) => {
      resolve(e.data.proof);
    };
    worker.postMessage({ type: 'generateProof', data: { seed, did } });
  });
}

// Usage
const proof = await generateProofInWorker(mySeed, myDid);
```

### Bundle Size

The WASM binary size depends on which build you use:

**Default build** (`./build.sh`):
- ~2-3 MB WASM binary
- Just proof generation APIs
- Recommended for production

**With PolymeshClient** (`./build_with_rust_client.sh`):
- ~3-5 MB WASM binary
- Includes PolymeshClient and signers
- For testing and development

Optimize bundle size with:

1. **Lazy Loading**: Load WASM only when needed
2. **Code Splitting**: Separate WASM from main bundle
3. **Compression**: Ensure server serves `.wasm` with gzip/brotli
4. **Use default build**: Don't build with PolymeshClient unless you need it

```typescript
// Lazy load WASM module
const loadDartWasm = () => import('@polymesh/dart-wasm');

// Only load when user needs it
button.onclick = async () => {
  const dart = await loadDartWasm();
  // ... use dart functions
};
```

### Polkadot.js vs PolymeshClient

- **Polkadot.js**: Smaller bundle, faster load, works with any chain, production-ready (recommended)
- **PolymeshClient**: Larger bundle, convenience methods, testing/development, requires different build script

For production browser apps, use Polkadot.js with the default build. For Node.js or desktop apps, either works fine.

## Troubleshooting

### Common Issues

#### 1. "WASM module not initialized"

**Problem**: Trying to use WASM functions before initialization completes.

**Solution**: Always await `init()` before using WASM:
```typescript
import init, { AccountKeys } from '@polymesh/dart-wasm';

// MUST call init first
await init();

// Now safe to use
const keys = new AccountKeys(seed);
```

#### 2. "Module parse failed" or "Unexpected token"

**Problem**: Bundler doesn't support WASM or async modules.

**Solution**: Update bundler configuration (see Integration Guide above).

#### 3. "Memory access out of bounds"

**Problem**: Passing invalid data to WASM functions.

**Solution**: Validate input data before passing to WASM:
```typescript
// Validate hex string length
if (seedHex.length !== 64) {
  throw new Error('Seed must be 64 hex characters (32 bytes)');
}

// Validate DID length
if (did.replace('0x', '').length !== 64) {
  throw new Error('DID must be 32 bytes (64 hex characters)');
}

// Validate amount
if (amount <= 0n) {
  throw new Error('Amount must be positive');
}
```

#### 4. "PolymeshClient is not defined"

**Problem**: Trying to use PolymeshClient when the default build was used.

**Solution**: Build different script that includes PolymeshClient:
```bash
./build_with_rust_client.sh
```

Then import and use PolymeshClient. If you only need the default proof generation APIs, you don't need this build - use the default `./build.sh` or the npm package instead.

#### 5. Performance issues or "out of memory"

**Problem**: Generating very large proofs or many proofs simultaneously.

**Solution**:
- Use Web Workers to parallelize work
- Process proofs sequentially instead of in parallel
- Increase available memory if possible

#### 6. TypeScript errors with WASM types

**Problem**: Missing type definitions or incorrect imports.

**Solution**: Ensure you're importing from the package correctly:
```typescript
// For npm package
import { AccountKeys } from '@polymesh/dart-wasm';

// For local builds
import { AccountKeys } from './pkg-web/polymesh_dart_wasm.js';

// TypeScript types are included in the package
```

#### 7. "Failed to decode" errors

**Problem**: Invalid serialized data or format mismatch.

**Solution**: Ensure data was serialized with the same version of the library:
```typescript
// Make sure you're using matching versions
const bytes = someProof.toBytes();  // From version X
const restored = SomeProof.fromBytes(bytes);  // Also from version X

// Don't mix versions or formats
```

### Debugging

Enable debug logging in the browser console:

```javascript
// Check WASM initialization
console.log('WASM available:', typeof window.polymesh_dart_wasm !== 'undefined');

// Monitor proof generation
const startTime = performance.now();
const proof = keys.registerAccountProof(did);
console.log('Proof generation took:', performance.now() - startTime, 'ms');
```

Check WASM memory usage (in Chrome DevTools):

```javascript
// In browser console
console.log(performance.memory);
```

Verify on-chain integration is working:

```typescript
// With Polkadot.js
const extrinsic = api.tx.confidentialAssets.registerAccount(proof.toBytes());
console.log('Extrinsic created successfully');

// Check if it will succeed by dry running
const res = await extrinsic.dryRun(signer);
console.log('Dry run result:', res);
```

## Additional Resources

- [wasm-bindgen Documentation](https://rustwasm.github.io/wasm-bindgen/)
- [WASM Pack Guide](https://rustwasm.github.io/wasm-pack/)
- [Polymesh DART Paper](https://assets.polymesh.network/P-DART-v1.pdf)
- [GitHub Repository](https://github.com/PolymeshAssociation/polymesh-dart)
