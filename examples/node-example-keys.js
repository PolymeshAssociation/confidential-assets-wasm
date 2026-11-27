// Node.js example for using Polymesh DART WASM
// Run with: node examples/node-example.js

//const WebSocket = require('ws');
Object.assign(global, { WebSocket: require('ws') });

const {
    AccountKeys,
    MasterSeed,
    generateMnemonic,
    AssetState,
    PolymeshClient,
    PolymeshSigner,
} = require('../pkg-node/polymesh_dart_wasm.js');

console.log('=== Polymesh DART WASM Node.js Example ===\n');

// 1. Generate a random mnemonic
console.log('1. Generating random mnemonic...');
const mnemonic = generateMnemonic();
console.log('   Mnemonic:', mnemonic);
console.log('');

// 2. Derive account keys from the mnemonic
console.log('2. Deriving account 0 keys from the mnemonic...');
const masterSeed = MasterSeed.fromMnemonic(mnemonic);
const accountKeys = masterSeed.deriveAccountKeys(0);
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
console.log('5. Recreating keys from the mnemonic...');
const recreatedKeys = MasterSeed.fromMnemonic(mnemonic).deriveAccountKeys(0);
const recreatedPublicKeys = recreatedKeys.publicKeys();
console.log('   Recreated public keys:', recreatedPublicKeys.toJson());

// Verify they match
if (publicKeys.toJson() === recreatedPublicKeys.toJson()) {
    console.log('   ✓ Keys match after recreating from the mnemonic!');
} else {
    console.log('   ✗ Error: Keys do not match!');
}
console.log('');

// 6. Export the secret keys and restore them
console.log('6. Restoring keys from toSecretKeyHex() (the private key; treat it like a seed)...');
const restoredKeys = AccountKeys.fromSecretKeyHex(accountKeys.toSecretKeyHex());
console.log('   Restored public keys:', restoredKeys.publicKeys().toJson());
console.log('');

// 7. Create an asset state
console.log('7. Creating an asset state...');
const assetId = 0;
const auditorPublicKeys = masterSeed.deriveAccountKeys(1).publicKeys();
const mediatorPublicKeys = masterSeed.deriveAccountKeys(2).publicKeys();
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

