# Polymesh DART WASM Development Guide

This guide provides detailed information for developers working with the Polymesh DART WASM bindings.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Building the WASM Package](#building-the-wasm-package)
3. [Integration Guide](#integration-guide)
4. [API Reference](#api-reference)
5. [Performance Considerations](#performance-considerations)
6. [Troubleshooting](#troubleshooting)

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
│   └── settlement.rs    # Settlement operations and proofs
├── examples/            # Example HTML and Node.js applications
├── tests/               # WASM-specific tests
├── Cargo.toml          # Rust dependencies and configuration
├── package.json        # NPM package metadata
└── build.sh            # Build script for all targets
```

### Data Flow

1. **Key Generation**: JavaScript → WASM → Rust crypto primitives → WASM → JavaScript
2. **Proof Generation**: Account state + Keys → WASM → Zero-knowledge proof → WASM → Serialized proof
3. **Proof Verification**: Serialized proof → WASM → Verification → Boolean result

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

### React Application

```typescript
import React, { useEffect, useState } from 'react';
import init, { AccountKeys, generateRandomSeed } from '@polymesh/dart-wasm';

function DartKeyManager() {
  const [wasmReady, setWasmReady] = useState(false);
  const [accountKeys, setAccountKeys] = useState<AccountKeys | null>(null);

  useEffect(() => {
    init().then(() => {
      setWasmReady(true);
    });
  }, []);

  const generateKeys = () => {
    if (!wasmReady) return;
    
    const seed = generateRandomSeed();
    const keys = new AccountKeys(seed);
    setAccountKeys(keys);
  };

  return (
    <div>
      {wasmReady ? (
        <button onClick={generateKeys}>Generate Keys</button>
      ) : (
        <p>Loading WASM...</p>
      )}
      
      {accountKeys && (
        <pre>{accountKeys.publicKeys().toJson()}</pre>
      )}
    </div>
  );
}
```

### Vue.js Application

```typescript
<template>
  <div>
    <button @click="generateKeys" :disabled="!wasmReady">
      Generate Keys
    </button>
    <pre v-if="publicKeys">{{ publicKeys }}</pre>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import init, { AccountKeys, generateRandomSeed } from '@polymesh/dart-wasm';

const wasmReady = ref(false);
const publicKeys = ref<string | null>(null);

onMounted(async () => {
  await init();
  wasmReady.value = true;
});

const generateKeys = () => {
  const seed = generateRandomSeed();
  const keys = new AccountKeys(seed);
  publicKeys.value = keys.publicKeys().toJson();
};
</script>
```

### Next.js Application

```typescript
// pages/dart-keys.tsx
import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';

// Dynamically import to avoid SSR issues
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
import type { AccountKeys } from '@polymesh/dart-wasm';

let dartWasm: typeof import('@polymesh/dart-wasm');

export default function DartKeyManager() {
  const [keys, setKeys] = useState<AccountKeys | null>(null);

  useEffect(() => {
    import('@polymesh/dart-wasm').then(async (module) => {
      dartWasm = module;
      await module.default(); // Initialize WASM
    });
  }, []);

  const generateKeys = () => {
    if (!dartWasm) return;
    const seed = dartWasm.generateRandomSeed();
    const newKeys = new dartWasm.AccountKeys(seed);
    setKeys(newKeys);
  };

  return (
    <div>
      <button onClick={generateKeys}>Generate Keys</button>
      {keys && <pre>{keys.publicKeys().toJson()}</pre>}
    </div>
  );
}
```

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

## API Reference

### Type Conversions

All WASM types provide serialization methods:

```typescript
// SCALE encoding (compact binary format)
const bytes: Uint8Array = accountKeys.toBytes();
const keys = AccountKeys.fromBytes(bytes);

// Hex encoding (for display/storage)
const hex: string = proof.toHex();
const proof = SenderAffirmationProof.fromHex(hex);

// JSON (for debugging only, not all types support this)
const json: string = publicKeys.toJson();
```

### Error Handling

All WASM functions that can fail return a `Result<T, JsValue>`:

```typescript
try {
  const keys = new AccountKeys(invalidSeed);
} catch (error) {
  console.error('Failed to create keys:', error);
}

// Or with async/await
try {
  await init();
  // ... use WASM functions
} catch (error) {
  console.error('WASM initialization failed:', error);
}
```

### Memory Management

WASM objects are automatically garbage collected. However, for large objects or tight loops, explicitly free them:

```typescript
// Create and use keys
const keys = new AccountKeys(seed);
const pubKeys = keys.publicKeys();

// ... use pubKeys

// When done, JavaScript GC will clean up
// No manual cleanup needed in most cases
```

## Performance Considerations

### Initialization

The WASM module initialization is asynchronous and should be done once:

```typescript
// Good: Initialize once at app startup
let wasmInitialized = false;

async function initWasm() {
  if (!wasmInitialized) {
    await init();
    wasmInitialized = true;
  }
}

// Bad: Initializing multiple times
await init(); // Called in component A
await init(); // Called in component B - unnecessary
```

### Batch Operations

When performing multiple operations, batch them to reduce JS ↔ WASM boundary crossings:

```typescript
// Good: Batch operations
const proofs = [];
for (let i = 0; i < 100; i++) {
  // All operations happen in WASM
  const keys = AccountKeys.fromSeed(`seed-${i}`);
  proofs.push(keys.publicKeys().toBytes());
}

// Less efficient: Many small WASM calls
for (let i = 0; i < 100; i++) {
  const keys = AccountKeys.fromSeed(`seed-${i}`);
  const pubKeys = keys.publicKeys();
  const acctKey = pubKeys.accountPublicKey();
  const encKey = pubKeys.encryptionPublicKey();
  // Multiple boundary crossings per iteration
}
```

### Proof Generation

Proof generation is CPU-intensive. Consider:

1. **Web Workers**: Offload proof generation to a worker thread
2. **Progress Updates**: For long operations, provide user feedback
3. **Caching**: Cache generated proofs when possible

```typescript
// Example with Web Worker
// worker.ts
import init, { AccountKeys } from '@polymesh/dart-wasm';

self.onmessage = async (e) => {
  await init();
  const keys = new AccountKeys(e.data.seed);
  const proof = keys.publicKeys().toBytes();
  self.postMessage({ proof });
};

// main.ts
const worker = new Worker(new URL('./worker.ts', import.meta.url));
worker.postMessage({ seed: 'my-seed' });
worker.onmessage = (e) => {
  console.log('Proof generated:', e.data.proof);
};
```

### Bundle Size

The WASM binary is approximately 2-5 MB. Optimize by:

1. **Lazy Loading**: Load WASM only when needed
2. **Code Splitting**: Separate WASM code from main bundle
3. **Compression**: Ensure your server serves `.wasm` files with gzip/brotli

```typescript
// Lazy load WASM module
const loadDartWasm = () => import('@polymesh/dart-wasm');

// Only load when user needs it
button.onclick = async () => {
  const dart = await loadDartWasm();
  await dart.default();
  // ... use dart functions
};
```

## Troubleshooting

### Common Issues

#### 1. "WASM module not initialized"

**Problem**: Trying to use WASM functions before initialization completes.

**Solution**:
```typescript
import init, { AccountKeys } from '@polymesh/dart-wasm';

// Wait for initialization
await init();

// Now safe to use
const keys = new AccountKeys(seed);
```

#### 2. "Module parse failed" or "Unexpected token"

**Problem**: Bundler doesn't support WASM or async modules.

**Solution**: Update bundler configuration (see Integration Guide above).

#### 3. "Memory access out of bounds"

**Problem**: Passing invalid data to WASM functions.

**Solution**: Validate input data:
```typescript
// Validate hex string length
if (seedHex.length !== 64) {
  throw new Error('Seed must be 64 hex characters');
}

// Validate bytes length
if (bytes.length !== 32) {
  throw new Error('Invalid byte length');
}
```

#### 4. Performance issues in development

**Problem**: Dev builds are unoptimized.

**Solution**: Use release builds for performance testing:
```bash
wasm-pack build --release --target web
```

#### 5. TypeScript errors with WASM types

**Problem**: Missing type definitions.

**Solution**: Ensure you're importing from the correct package build:
```typescript
// For bundlers
import { AccountKeys } from '@polymesh/dart-wasm';

// For web (if using pkg-web directly)
import { AccountKeys } from './pkg-web/polymesh_dart_wasm.js';
```

### Debugging

Enable debug logging:

```typescript
// In browser console
localStorage.debug = 'polymesh:*';

// Or in code
console.log('WASM version:', dartWasm.version());
```

Check WASM memory usage:

```typescript
// In browser
console.log(performance.memory);
```

## Additional Resources

- [wasm-bindgen Documentation](https://rustwasm.github.io/wasm-bindgen/)
- [WASM Pack Guide](https://rustwasm.github.io/wasm-pack/)
- [Polymesh DART Paper](https://assets.polymesh.network/P-DART-v1.pdf)
- [GitHub Repository](https://github.com/PolymeshAssociation/polymesh-dart)
