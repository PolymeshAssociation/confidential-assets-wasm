// Node.js example for using Polymesh DART WASM
// Run with: node examples/node-example.js

const {
    AccountKeys,
    generateRandomSeed,
    AssetState
} = require('../pkg-node/polymesh_dart_wasm.js');

console.log('=== Polymesh DART WASM Node.js Example ===\n');

// 1. Generate a random seed
console.log('1. Generating random seed...');
const seed = generateRandomSeed();
console.log('   Seed:', seed);
console.log('');

// 2. Create account keys from seed
console.log('2. Creating account keys from seed...');
const accountKeys = new AccountKeys(seed);
console.log('   ✓ Account keys created');
console.log('');

// 3. Get public keys
console.log('3. Extracting public keys...');
const publicKeys = accountKeys.publicKeys();
console.log('   Public keys JSON:');
console.log('  ', publicKeys.toJson());
console.log('');

// 4. Get individual key components
console.log('4. Getting individual key components...');
const accountPubKey = publicKeys.accountPublicKey();
const encryptionPubKey = publicKeys.encryptionPublicKey();
console.log('   Account public key:', accountPubKey.toJson());
console.log('   Encryption public key:', encryptionPubKey.toJson());
console.log('');

// 5. Export and import keys
console.log('5. Testing key export/import...');
const keyBytes = accountKeys.toBytes();
console.log('   Exported key bytes length:', keyBytes.length);

const reimportedKeys = AccountKeys.fromBytes(keyBytes);
const reimportedPublicKeys = reimportedKeys.publicKeys();
console.log('   Re-imported public keys:', reimportedPublicKeys.toJson());

// Verify they match
if (publicKeys.toJson() === reimportedPublicKeys.toJson()) {
    console.log('   ✓ Keys match after re-import!');
} else {
    console.log('   ✗ Error: Keys do not match!');
}
console.log('');

// 6. Create keys from a string seed
console.log('6. Creating keys from a string seed...');
const stringKeys = AccountKeys.fromSeed('my-secret-password-seed');
const stringPublicKeys = stringKeys.publicKeys();
console.log('   Public keys from string seed:', stringPublicKeys.toJson());
console.log('');

// 7. Create an asset state
console.log('7. Creating an asset state...');
const assetId = 42;
const mediators = []; // Array of EncryptionPublicKey bytes
const auditors = [];  // Array of EncryptionPublicKey bytes

try {
    const assetState = new AssetState(assetId, mediators, auditors);
    console.log('   ✓ Asset state created');
    console.log('   Asset ID:', assetState.assetId());
    console.log('   Mediators:', assetState.mediatorCount());
    console.log('   Auditors:', assetState.auditorCount());

    const assetBytes = assetState.toBytes();
    console.log('   Asset state bytes length:', assetBytes.length);
} catch (error) {
    console.log('   Note: Asset state creation requires encryption keys for mediators/auditors');
}
console.log('');

console.log('=== Example Complete ===');
