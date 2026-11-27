// Node.js example for using Polymesh DART WASM
// Run with: node examples/node-example.js

//const WebSocket = require('ws');
Object.assign(global, { WebSocket: require('ws') });

const {
    AccountKeys,
    generateRandomSeed,
    AssetState,
    PolymeshClient,
    PolymeshSigner,
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
console.log('5. Recreating keys from the seed...');
const recreatedKeys = new AccountKeys(seed);
const recreatedPublicKeys = recreatedKeys.publicKeys();
console.log('   Recreated public keys:', recreatedPublicKeys.toJson());

// Verify they match
if (publicKeys.toJson() === recreatedPublicKeys.toJson()) {
    console.log('   ✓ Keys match after recreating from the seed!');
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
const assetId = 0;
const auditorPublicKeys = AccountKeys.fromSeed('auditor-seed').publicKeys();
const mediatorPublicKeys = AccountKeys.fromSeed('mediator-seed').publicKeys();
// Same shape as the chain's `confidentialAssets.keys(assetId)` value.
const assetKeys = {
    encKeys: [
        auditorPublicKeys.encryptionPublicKey().toJs(),
        mediatorPublicKeys.encryptionPublicKey().toJs(),
    ],
    mediators: [mediatorPublicKeys.accountPublicKey().toJs()],
};

try {
    const assetState = new AssetState(assetId, assetKeys);
    console.log('   ✓ Asset state created');
    console.log('   Asset ID:', assetState.assetId());
    console.log('   Mediators:', assetState.mediatorCount());
    console.log('   Encryption keys:', assetState.auditorCount());
    console.log('   Frozen:', assetState.isFrozen());

    const assetBytes = assetState.toBytes();
    console.log('   Asset state bytes length:', assetBytes.length);
} catch (error) {
    console.log('   ✗ Error creating asset state:', error);
}
console.log('');

// Generate account registration proof.
console.log('8. Generating account registration proof...');
const did = new Uint8Array(32);
const registrationProof = accountKeys.registerAccountProof(did);

console.log('   Registration proof bytes length:', registrationProof.toBytes().length);

// Generate account asset registration.
console.log('9. Generating account asset registration...');
const assetRegistration = accountKeys.registerAccountAssetProof(assetId, did);

console.log('   Account asset registration proof bytes length:', assetRegistration.getProofBytes().length);

