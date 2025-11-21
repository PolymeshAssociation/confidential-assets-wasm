# Quick Start Guide - Polymesh DART WASM

Get up and running with Polymesh DART WASM bindings in minutes!

## ⚠️ Important: Chain Integration is Optional

This library generates zero-knowledge proofs for confidential transactions. You have flexibility in how you submit these proofs to the blockchain:

- **With Polkadot.js (Recommended)**: Lightweight, flexible, minimal dependencies
- **With PolymeshClient** (Testing/Development only): Requires `./build_with_rust_client.sh` script
- **Your own chain client**: Use any solution that works for you

The core WASM APIs (proof generation, key management) work independently and don't require PolymeshClient.

## Installation

### For NPM/Yarn users

```bash
npm install @polymesh/dart-wasm
```

This installs the default build with core proof generation APIs.

### For local development with PolymeshClient (optional)

If you want to use `PolymeshClient` and `PolymeshSigner` for testing:

```bash
cd polymesh-dart-wasm
./build_with_rust_client.sh
```

### Standard local development build

```bash
cd polymesh-dart-wasm
./build.sh
```

## Your First DART Application

### Browser (Vanilla JavaScript)

Create an HTML file:

```html
<!DOCTYPE html>
<html>
<head>
    <title>My First DART App</title>
</head>
<body>
    <h1>Polymesh DART Demo</h1>
    <button id="createKeys">Create Keys</button>
    <pre id="output"></pre>

    <script type="module">
        import init, { AccountKeys, generateRandomSeed } 
            from './pkg-web/polymesh_dart_wasm.js';

        // Initialize WASM
        await init();

        document.getElementById('createKeys').onclick = () => {
            // Generate keys
            const seed = generateRandomSeed();
            const keys = new AccountKeys(seed);
            const pubKeys = keys.publicKeys();
            
            // Display results
            document.getElementById('output').textContent = 
                'Seed: ' + seed + '\n\n' +
                'Public Keys:\n' + JSON.stringify({
                  accountKey: pubKeys.accountPublicKey().toJson(),
                  encryptionKey: pubKeys.encryptionPublicKey().toJson()
                }, null, 2);
        };
    </script>
</body>
</html>
```

Serve with a local server:
```bash
python3 -m http.server 8000
# Visit http://localhost:8000
```

### Node.js

Create `app.js`:

```javascript
const { AccountKeys, generateRandomSeed } = 
    require('./pkg-node/polymesh_dart_wasm.js');

// Generate account keys
const seed = generateRandomSeed();
console.log('Seed:', seed);

const keys = new AccountKeys(seed);
const pubKeys = keys.publicKeys();

console.log('Account public key:', pubKeys.accountPublicKey().toJson());
console.log('Encryption public key:', pubKeys.encryptionPublicKey().toJson());
```

Run it:
```bash
node app.js
```

### TypeScript

Create `app.ts`:

```typescript
import init, { 
    AccountKeys, 
    AccountPublicKeys,
    AssetState,
    generateRandomSeed 
} from '@polymesh/dart-wasm';

async function main() {
    // Initialize WASM
    await init();
    
    // Generate keys
    const seed: string = generateRandomSeed();
    const keys: AccountKeys = new AccountKeys(seed);
    const pubKeys: AccountPublicKeys = keys.publicKeys();
    
    console.log('Seed:', seed);
    console.log('Account key:', pubKeys.accountPublicKey().toJson());
    console.log('Encryption key:', pubKeys.encryptionPublicKey().toJson());
}

main().catch(console.error);
```

Compile and run:
```bash
tsc app.ts
node app.js
```

## Common Use Cases

### 1. Create and Store Account Keys

```javascript
import { AccountKeys, generateRandomSeed } from '@polymesh/dart-wasm';

// Generate new keys
const seed = generateRandomSeed();
const keys = new AccountKeys(seed);

// Export for storage (encrypt before storing!)
const keyBytes = keys.toBytes();
localStorage.setItem('dartKeys', JSON.stringify(Array.from(keyBytes)));
localStorage.setItem('dartSeed', seed);

// Later: Restore from storage
const storedBytes = JSON.parse(localStorage.getItem('dartKeys'));
const restoredKeys = AccountKeys.fromBytes(new Uint8Array(storedBytes));
```

### 2. Share Public Keys

```javascript
// Get public keys to share
const pubKeys = keys.publicKeys();
const accountPubKey = pubKeys.accountPublicKey();
const encryptionPubKey = pubKeys.encryptionPublicKey();

// Export as JSON for display
console.log('Share these public keys:');
console.log({
  account: accountPubKey.toJson(),
  encryption: encryptionPubKey.toJson()
});
```

### 3. Register Account on-Chain (Proof Generation)

```javascript
import { AccountKeys } from '@polymesh/dart-wasm';

// Your keys and DID
const keys = new AccountKeys(seed);
const myDid = '0x1234...'; // Your identity

// Generate registration proof (without submitting to chain)
const proof = keys.registerAccountProof(myDid);
const proofBytes = proof.toBytes();
const proofHex = proof.toHex();

console.log('Generated proof - ready to submit to chain');
// Now use your chain client (Polkadot.js, PolymeshClient, etc.)
// to submit this proof
```

### 4. Work with Asset States

```javascript
import { AssetState, EncryptionPublicKey } from '@polymesh/dart-wasm';

// Option A: From Polkadot.js chain query
const assetId = 42;
const assetDetail = await api.query.confidentialAssets.dartAssetDetails(assetId);
const assetState = new AssetState(assetId, assetDetail.mediators, assetDetail.auditors);

// Option B: From raw hex strings
const mediatorKey = new EncryptionPublicKey('0xabcd...');
const auditorKey = new EncryptionPublicKey('0x5678...');
const assetState = new AssetState(assetId, [mediatorKey], [auditorKey]);

console.log('Asset ID:', assetState.assetId());
console.log('Mediators:', assetState.mediatorCount());
console.log('Auditors:', assetState.auditorCount());

// Export asset state
const assetBytes = assetState.toBytes();
```

### 5. Deterministic Key Generation

```javascript
// Same seed always produces same keys
const keys1 = AccountKeys.fromSeed('my-password');
const keys2 = AccountKeys.fromSeed('my-password');

// These will be identical
console.assert(
  keys1.publicKeys().accountPublicKey().toJson() === 
  keys2.publicKeys().accountPublicKey().toJson()
);
```

## Next Steps

1. **Read the Full Documentation**: See [README.md](README.md) for complete API reference
2. **Explore Examples**: Check the `examples/` directory for more complex scenarios
3. **Development Guide**: Read [DEVELOPMENT.md](DEVELOPMENT.md) for integration patterns
4. **Learn DART**: Review the [P-DART paper](https://assets.polymesh.network/P-DART-v1.pdf) for protocol details
5. **Chain Integration**: 
   - See [README.md - Using with Polkadot.js](README.md#using-with-polkadotjs-without-polymeshclient) for examples
   - See [DEVELOPMENT.md](DEVELOPMENT.md) for PolymeshClient integration (optional)

## Troubleshooting

### Issue: "Cannot find module '@polymesh/dart-wasm'"

Make sure you've built the package or installed it via npm:
```bash
cd polymesh-dart-wasm
./build.sh
```

### Issue: "WASM module not initialized"

Always call `init()` before using other functions:
```javascript
await init(); // Important!
const keys = new AccountKeys(seed); // Now this works
```

### Issue: Bundler errors with WASM

Update your bundler config to support WASM modules. See [DEVELOPMENT.md](DEVELOPMENT.md) for specific bundler configurations.

### Issue: "Proof generation" or "Proof verification" errors

Ensure your input data is valid:
- DIDs should be 32 bytes (64 hex characters)
- Asset IDs should be valid numbers
- Keys should come from the same seed generation
- AssetState mediators/auditors should match chain data

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/PolymeshAssociation/polymesh-dart/issues)
- **Discussions**: [GitHub Discussions](https://github.com/PolymeshAssociation/polymesh-dart/discussions)
- **Documentation**: [Full API Docs](README.md)

## PolymeshClient vs. Polkadot.js

**Use Polkadot.js if you:**
- Are building production applications
- Want minimal dependencies
- Are already using Polkadot.js in your project
- Want maximum flexibility with chain interactions
- Want the smallest bundle size (recommended)

**Use PolymeshClient if you:**
- Are testing or developing proof generation
- Want convenience Polymesh-specific operations
- Are building desktop or Node.js applications (not browser)
- Don't mind the extra build step (`./build_with_rust_client.sh`)
- Don't mind the larger bundle size

**To use PolymeshClient**, you must build with:
```bash
./build_with_rust_client.sh
```

This is NOT the default build. The default `./build.sh` creates a minimal bundle with just proof generation APIs.

Both approaches work equally well with the core WASM proof generation!

Happy building! 🚀
