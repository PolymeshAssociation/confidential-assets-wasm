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

async function main() {
    const client = await new PolymeshClient("ws://localhost:9944");
    console.log('   ✓ Connected to Polymesh node');
    console.log('   Client:', client);
    console.log('');

    // Create some test users and onboard them if needed.
    console.log('Creating and onboarding test issuer...');
    const issuer = client.newSigner("//TestIssuer");
    // Check if the signer has an identity
    const issuer_did = await issuer.identity();
    if (issuer_did === null) {
        console.log('   No identity found for signer, onboarding account...');
        await client.onboardSigner(issuer);
        console.log('   ✓ Account onboarded');
    } else {
        console.log('   Signer identity DID:', issuer_did);
    }
    console.log('');

    // Create and onboard an investor.
    console.log('Creating and onboarding test investor...');
    const investor = client.newSigner("//TestInvestor");
    const investor_did = await investor.identity();
    if (investor_did === null) {
        console.log('   No identity found for signer, onboarding account...');
        await client.onboardSigner(investor);
        console.log('   ✓ Account onboarded');
    } else {
        console.log('   Signer identity DID:', investor_did);
    }
    console.log('');

    // Create and onboard an mediator (sometimes used as an auditor).
    console.log('Creating and onboarding test mediator...');
    const mediator = client.newSigner("//TestMediator");
    const mediator_did = await mediator.identity();
    if (mediator_did === null) {
        console.log('   No identity found for signer, onboarding account...');
        await client.onboardSigner(mediator);
        console.log('   ✓ Account onboarded');
    } else {
        console.log('   Signer identity DID:', mediator_did);
    }
    console.log('');

    // Create account keys from seed
    console.log('Creating account keys for test issuer...');
    const issuerKeys = AccountKeys.fromSeed("Test-Issuer-seed");
    const issuerPublicKeys = issuerKeys.publicKeys();
    console.log('   Public keys JSON:');
    console.log('  ', issuerPublicKeys.toJson());
    console.log('');

    // Register the issuer's account keys if not already registered
    const issuerAccountDid = await client.getAccountIdentity(issuerPublicKeys.accountPublicKey());
    if (issuerAccountDid === null) {
        console.log('   No account identity found for issuer keys, registering account keys...');
        const issuerRegistrationProof = issuerKeys.registerAccountProof(issuer_did);
        const txHash = await issuer.registerAccount(issuerRegistrationProof);
        console.log('   ✓ Account keys registered with tx hash:', txHash);
    } else {
        console.log('   Account identity DID for issuer keys:', issuerAccountDid);
    }

    // Create account keys for test investor
    console.log('Creating account keys for test investor...');
    const investorKeys = AccountKeys.fromSeed("Test-Investor-seed");
    const investorPublicKeys = investorKeys.publicKeys();
    console.log('   Public keys JSON:');
    console.log('  ', investorPublicKeys.toJson());
    console.log('');

    // Register the investor's account keys if not already registered
    const investorAccountDid = await client.getAccountIdentity(investorPublicKeys.accountPublicKey());
    if (investorAccountDid === null) {
        console.log('   No account identity found for investor keys, registering account keys...');
        const investorRegistrationProof = investorKeys.registerAccountProof(investor_did);
        const txHash = await investor.registerAccount(investorRegistrationProof);
        console.log('   ✓ Account keys registered with tx hash:', txHash);
    } else {
        console.log('   Account identity DID for investor keys:', investorAccountDid);
    }
    console.log('');

    // Create account keys for test mediator
    console.log('Creating account keys for test mediator...');
    const mediatorKeys = AccountKeys.fromSeed("Test-Mediator-seed");
    const mediatorPublicKeys = mediatorKeys.publicKeys();
    const mediatorEncryptionKey = mediatorPublicKeys.encryptionPublicKey();
    console.log('   Public keys JSON:');
    console.log('  ', mediatorPublicKeys.toJson());
    console.log('');

    // Register the mediator's account keys if not already registered
    const mediatorAccountDid = await client.getAccountIdentity(mediatorPublicKeys.accountPublicKey());
    if (mediatorAccountDid === null) {
        console.log('   No account identity found for mediator keys, registering account keys...');
        const mediatorRegistrationProof = mediatorKeys.registerAccountProof(mediator_did);
        const txHash = await mediator.registerAccount(mediatorRegistrationProof);
        console.log('   ✓ Account keys registered with tx hash:', txHash);
    } else {
        console.log('   Account identity DID for mediator keys:', mediatorAccountDid);
    }
    console.log('');

    // 7. Create an asset state
    console.log('Creating an asset state...');
    const mediators = [];
    const auditors = [mediatorEncryptionKey]; // Just use mediator as auditor for this example.

    // Create the asset on-chain using the issuer signer.
    console.log('Creating confidential asset on-chain...');
    var assetId = null;
    try {
        const results = await issuer.createAsset(mediators, auditors, "Test Confidential Asset");
        const assetState = results.assetState();
        assetId = assetState.assetId();
        console.log('   ✓ Confidential asset created with Asset ID:', assetId);
        console.log('   ✓ Asset state created block hash:', results.blockHash());
        console.log('   Asset ID:', assetState.assetId());
        console.log('   Mediators:', assetState.mediatorCount());
        console.log('   Auditors:', assetState.auditorCount());
        console.log('');
    } catch (e) {
        console.error('   ✗ Error creating confidential asset:', e);
        process.exit(1);
    }

    // Register the issuer's account with the new asset.
    console.log('Registering issuer account with the new asset...');
    const assetRegistration = issuerKeys.registerAccountAssetProof(assetId, issuer_did);
    var issuerAccountState = assetRegistration.getAccountAssetState();
    console.log('   Account asset registration proof bytes length:', assetRegistration.getProofBytes().length);
    try {
        const results = await issuer.registerAccountAsset(assetRegistration.getProof());
        // commit pending state to account state
        const leaf = results.leafIndex();
        console.log('  Account leaf index from tx results:', leaf);
        issuerAccountState.commitPendingState(leaf);
        console.log('   ✓ Issuer account registered with asset with tx hash:', results.blockHash());
        console.log('   Account Asset State:', issuerAccountState.toJson());
        console.log('   Issuer Account Leaf Index:', leaf);
        console.log('');
    } catch (e) {
        console.error('   ✗ Error registering issuer account with asset:', e);
        process.exit(1);
    }

    // Get the account curve tree.
    console.log('Getting account curve tree...');
    const accountCurveTree = await client.getAccountCurveTree();
    console.log('   ✓ Retrieved account curve tree');
    console.log('   Account Curve Tree:', accountCurveTree);
    console.log('');

    // Mint some asset to the into the issuer's account.
    try {
        const leaf = issuerAccountState.leafIndex();
        console.log('Get the path to the issuer account leaf: ', leaf);
        const issuerAccountLeafPath = await accountCurveTree.getAccountLeafPath(leaf);

        // The issuer's account balance before minting
        console.log('   Issuer Account Asset State before minting:', issuerAccountState.balance());

        // Generate minting proof
        console.log('Generating asset minting proof for issuer account...');
        const mintAmount = 1000;
        const mintingProof = issuerAccountState.assetMintingProof(
            issuerKeys,
            issuerAccountLeafPath,
            mintAmount
        );
        console.log('   ✓ Generated asset minting proof');
        console.log('   Minting Proof Bytes Length:', mintingProof.toBytes().length);

        // Mint the asset
        console.log('Minting asset to issuer account...');
        const results = await issuer.mintAsset(mintingProof);
        // Commit pending state to account state
        const newLeaf = results.leafIndex();
        console.log('  New Account leaf index from tx results:', newLeaf);
        issuerAccountState.commitPendingState(newLeaf);

        // The issuer's account balance after minting
        console.log('   Issuer Account Asset Balance after minting:', issuerAccountState.balance());

        console.log('   Account Asset State after minting:', issuerAccountState.toJson());
        console.log('   ✓ Minted asset with tx hash:', results.blockHash());
        console.log('');
    } catch (e) {
        console.error('   ✗ Error getting issuer account leaf path:', e);
        process.exit(1);
    }

    // Register the investor's account with the new asset.
    console.log('Registering investor account with the new asset...');
    const investorAssetRegistration = investorKeys.registerAccountAssetProof(assetId, investor_did);
    var investorAccountState = investorAssetRegistration.getAccountAssetState();
    console.log('   Account asset registration proof bytes length:', investorAssetRegistration.getProofBytes().length);
    try {
        const results = await investor.registerAccountAsset(investorAssetRegistration.getProof());
        // commit pending state to account state
        const leaf = results.leafIndex();
        console.log('  Account leaf index from tx results:', leaf);
        investorAccountState.commitPendingState(leaf);
        console.log('   ✓ Investor account registered with asset with tx hash:', results.blockHash());
        console.log('   Account Asset State:', investorAccountState.toJson());
        console.log('');
    } catch (e) {
        console.error('   ✗ Error registering investor account with asset:', e);
        process.exit(1);
    }

    // Get the asset curve tree.
    console.log('Getting asset curve tree...');
    const assetCurveTree = await client.getAssetCurveTree();
    console.log('   ✓ Retrieved asset curve tree');
    console.log('   Asset Curve Tree:', assetCurveTree);
    console.log('');

    // Create an asset leaf path builder.
    console.log('Creating asset leaf path builder...');
    const assetLeafPathBuilder = await assetCurveTree.buildAssetLeafPaths();
    console.log('   ✓ Created asset leaf path builder');
    console.log('   Asset Leaf Path Builder:', assetLeafPathBuilder);
    console.log('');

    // Track an asset and get it's current state.
    console.log('Tracking asset state...');
    const assetState = await assetLeafPathBuilder.trackAsset(assetId);
    console.log('   ✓ Tracked asset state');
    console.log('   Asset State:', assetState);
    console.log('   Mediators:', assetState.mediatorCount());
    console.log('   Auditors:', assetState.auditorCount());
    console.log('');

    console.log('=== Example Complete ===');
    process.exit(0);
}

main();