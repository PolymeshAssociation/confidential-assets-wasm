# Quick Start Guide - Polymesh DART WASM

Get up and running with Polymesh DART WASM bindings in minutes!

## Installation

### For NPM/Yarn users

```bash
npm install @polymesh/dart-wasm
# or
yarn add @polymesh/dart-wasm
```

### For local development

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
                'Public Keys:\n' + pubKeys.toJson();
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
    require('@polymesh/dart-wasm');

// Generate account keys
const seed = generateRandomSeed();
console.log('Seed:', seed);

const keys = new AccountKeys(seed);
const pubKeys = keys.publicKeys();

console.log('Public Keys:', pubKeys.toJson());
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
    generateRandomSeed 
} from '@polymesh/dart-wasm';

async function main() {
    // Initialize WASM
    await init();
    
    // Generate keys
    const seed = generateRandomSeed();
    const keys = new AccountKeys(seed);
    const pubKeys = keys.publicKeys();
    
    console.log('Seed:', seed);
    console.log('Public Keys:', pubKeys.toJson());
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

// Export for storage
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

// Export as bytes for transmission
const accountBytes = accountPubKey.toBytes();
const encryptionBytes = encryptionPubKey.toBytes();

// Or as JSON for display
console.log('Share these public keys:');
console.log(pubKeys.toJson());
```

### 3. Work with Asset States

```javascript
import { AssetState } from '@polymesh/dart-wasm';

// Create an asset with ID 42, no mediators/auditors
const assetId = 42;
const asset = new AssetState(assetId, [], []);

console.log('Asset ID:', asset.assetId());
console.log('Mediators:', asset.mediatorCount());
console.log('Auditors:', asset.auditorCount());

// Export asset state
const assetBytes = asset.toBytes();
```

### 4. Handle Proofs

```javascript
import { AccountAssetRegistrationProof } from '@polymesh/dart-wasm';

// Assume you have a proof from somewhere
const proofBytes = getProofFromSomewhere();

// Import the proof
const proof = AccountAssetRegistrationProof.fromBytes(proofBytes);

// Export as hex for display/transmission
const proofHex = proof.toHex();
console.log('Proof (hex):', proofHex);

// Later: Import from hex
const reimportedProof = AccountAssetRegistrationProof.fromHex(proofHex);
```

### 5. Deterministic Key Generation

```javascript
// Same seed always produces same keys
const keys1 = AccountKeys.fromSeed('my-password');
const keys2 = AccountKeys.fromSeed('my-password');

// These will be identical
console.log(keys1.publicKeys().toJson() === keys2.publicKeys().toJson()); // true
```

## Next Steps

1. **Read the Full Documentation**: See [README.md](README.md) for complete API reference
2. **Explore Examples**: Check the `examples/` directory for more complex scenarios
3. **Development Guide**: Read [DEVELOPMENT.md](DEVELOPMENT.md) for integration patterns
4. **Learn DART**: Review the [P-DART paper](https://assets.polymesh.network/P-DART-v1.pdf) for protocol details

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

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/PolymeshAssociation/polymesh-dart/issues)
- **Discussions**: [GitHub Discussions](https://github.com/PolymeshAssociation/polymesh-dart/discussions)
- **Documentation**: [Full API Docs](README.md)

Happy building! 🚀
