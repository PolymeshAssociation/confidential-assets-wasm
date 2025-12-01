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
    SettlementBuilder,
    LegBuilder,
} = require('../pkg-node/polymesh_dart_wasm.js');

console.log('=== Polymesh DART WASM Node.js Example ===\n');

async function main() {
    const client = await PolymeshClient.connect("ws://localhost:9944");
    console.log('   ✓ Connected to Polymesh node');
    console.log('   Client:', client);
    console.log('');

    // Set whether to finalize transactions or not (for faster testing).
    client.finalize = false;
    console.log('   ✓ Set client finalize to false for faster testing');
    console.log('');

    // Create some test users and onboard them if needed.
    console.log('Creating and onboarding test issuer...');
    const issuer = client.newSigner("//TestIssuer");
    // Check if the signer has an identity
    var issuer_did = await issuer.identity();
    if (issuer_did === null) {
        console.log('   No identity found for signer, onboarding account...');
        await client.onboardSigner(issuer);

        issuer_did = await issuer.identity();
        console.log('   ✓ Account onboarded DID:', issuer_did);
    } else {
        console.log('   Signer identity DID:', issuer_did);
    }
    console.log('');

    // Create and onboard some investors.
    console.log('Creating and onboarding test investor 1...');
    const investor1 = client.newSigner("//TestInvestor1");
    var investor1_did = await investor1.identity();
    if (investor1_did === null) {
        console.log('   No identity found for signer, onboarding account...');
        await client.onboardSigner(investor1);

        investor1_did = await investor1.identity();
        console.log('   ✓ Account onboarded DID:', investor1_did);
    } else {
        console.log('   Signer identity DID:', investor1_did);
    }
    console.log('');

    console.log('Creating and onboarding test investor 2...');
    const investor2 = client.newSigner("//TestInvestor2");
    var investor2_did = await investor2.identity();
    if (investor2_did === null) {
        console.log('   No identity found for signer, onboarding account...');
        await client.onboardSigner(investor2);

        investor2_did = await investor2.identity();
        console.log('   ✓ Account onboarded DID:', investor2_did);
    } else {
        console.log('   Signer identity DID:', investor2_did);
    }
    console.log('');

    // Create and onboard an mediator (sometimes used as an auditor).
    console.log('Creating and onboarding test mediator...');
    const mediator = client.newSigner("//TestMediator");
    var mediator_did = await mediator.identity();
    if (mediator_did === null) {
        console.log('   No identity found for signer, onboarding account...');
        await client.onboardSigner(mediator);

        mediator_did = await mediator.identity();
        console.log('   ✓ Account onboarded DID:', mediator_did);
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
        console.log('   Registration proof bytes length:', issuerRegistrationProof.toBytes().length);
        const txHash = await issuer.registerAccount(issuerRegistrationProof);
        console.log('   ✓ Account keys registered with tx hash:', txHash);
    } else {
        console.log('   Account identity DID for issuer keys:', issuerAccountDid);
    }

    // Create account keys for the investors.
    console.log('Creating account keys for test investor 1...');
    const investor1Keys = AccountKeys.fromSeed("Test-Investor1-seed");
    const investor1PublicKeys = investor1Keys.publicKeys();
    console.log('   Public keys JSON:');
    console.log('  ', investor1PublicKeys.toJson());
    console.log('');

    // Register the investor 1's account keys if not already registered
    const investor1AccountDid = await client.getAccountIdentity(investor1PublicKeys.accountPublicKey());
    if (investor1AccountDid === null) {
        console.log('   No account identity found for investor keys, registering account keys...');
        const investorRegistrationProof = investor1Keys.registerAccountProof(investor1_did);
        console.log('   Registration proof bytes length:', investorRegistrationProof.toBytes().length);
        const txHash = await investor1.registerAccount(investorRegistrationProof);
        console.log('   ✓ Account keys registered with tx hash:', txHash);
    } else {
        console.log('   Account identity DID for investor keys:', investor1AccountDid);
    }
    console.log('');

    console.log('Creating account keys for test investor 2...');
    const investor2Keys = AccountKeys.fromSeed("Test-Investor2-seed");
    const investor2PublicKeys = investor2Keys.publicKeys();
    console.log('   Public keys JSON:');
    console.log('  ', investor2PublicKeys.toJson());
    console.log('');

    // Register the investor 2's account keys if not already registered
    const investor2AccountDid = await client.getAccountIdentity(investor2PublicKeys.accountPublicKey());
    if (investor2AccountDid === null) {
        console.log('   No account identity found for investor keys, registering account keys...');
        const investorRegistrationProof = investor2Keys.registerAccountProof(investor2_did);
        console.log('   Registration proof bytes length:', investorRegistrationProof.toBytes().length);
        const txHash = await investor2.registerAccount(investorRegistrationProof);
        console.log('   ✓ Account keys registered with tx hash:', txHash);
    } else {
        console.log('   Account identity DID for investor keys:', investor2AccountDid);
    }
    console.log('');

    // Create account keys for test mediator
    console.log('Creating account keys for test mediator...');
    const mediatorKeys = AccountKeys.fromSeed("Test-Mediator-seed");
    const mediatorEncryptionKey = mediatorKeys.encryptionKeyPair();
    const mediatorPublicKeys = mediatorKeys.publicKeys();
    const mediatorEncryptionPublicKey = mediatorPublicKeys.encryptionPublicKey();
    console.log('   Public keys JSON:');
    console.log('  ', mediatorPublicKeys.toJson());
    console.log('');

    // Register the mediator's account keys if not already registered
    const mediatorAccountDid = await client.getAccountIdentity(mediatorPublicKeys.accountPublicKey());
    if (mediatorAccountDid === null) {
        console.log('   No account identity found for mediator keys, registering account keys...');
        const mediatorRegistrationProof = mediatorKeys.registerAccountProof(mediator_did);
        console.log('   Registration proof bytes length:', mediatorRegistrationProof.toBytes().length);
        const txHash = await mediator.registerAccount(mediatorRegistrationProof);
        console.log('   ✓ Account keys registered with tx hash:', txHash);
    } else {
        console.log('   Account identity DID for mediator keys:', mediatorAccountDid);
    }
    console.log('');

    // Create the asset on-chain using the issuer signer.
    console.log('Creating confidential asset on-chain...');
    var assetId = null;
    try {
        const mediators = [];
        const auditors = [mediatorEncryptionPublicKey]; // Just use mediator as auditor for this example.
        const results = await issuer.createAsset("Test name", "TST", 2, mediators, auditors, "Test Confidential Asset metadata");
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
    const mintAmount = 1000;
    try {
        const leaf = issuerAccountState.leafIndex();
        console.log('Get the path to the issuer account leaf: ', leaf);
        const issuerAccountLeafPath = await accountCurveTree.getLeafPathAndRoot(leaf);

        // The issuer's account balance before minting
        console.log('   Issuer Account Asset State before minting:', issuerAccountState.balance());

        // Generate minting proof
        console.log('Generating asset minting proof for issuer account...');
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

    // Register the investor 1 account with the new asset.
    console.log('Registering investor 1 account with the new asset...');
    const investorAssetRegistration = investor1Keys.registerAccountAssetProof(assetId, investor1_did);
    var investorAccountState = investorAssetRegistration.getAccountAssetState();
    console.log('   Account asset registration proof bytes length:', investorAssetRegistration.getProofBytes().length);
    try {
        const results = await investor1.registerAccountAsset(investorAssetRegistration.getProof());
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

    // Register the investor 2 account with the new asset.
    console.log('Registering investor 2 account with the new asset...');
    const investor2AssetRegistration = investor2Keys.registerAccountAssetProof(assetId, investor2_did);
    var investor2AccountState = investor2AssetRegistration.getAccountAssetState();
    console.log('   Account asset registration proof bytes length:', investor2AssetRegistration.getProofBytes().length);
    try {
        const results = await investor2.registerAccountAsset(investor2AssetRegistration.getProof());
        // commit pending state to account state
        const leaf = results.leafIndex();
        console.log('  Account leaf index from tx results:', leaf);
        investor2AccountState.commitPendingState(leaf);
        console.log('   ✓ Investor 2 account registered with asset with tx hash:', results.blockHash());
        console.log('   Account Asset State:', investor2AccountState.toJson());
        console.log('');
    } catch (e) {
        console.error('   ✗ Error registering investor 2 account with asset:', e);
        process.exit(1);
    }

    // Get the asset curve tree.
    console.log('Getting asset curve tree...');
    const assetCurveTree = await client.getAssetCurveTree();
    console.log('   ✓ Retrieved asset curve tree');
    console.log('   Asset Curve Tree:', assetCurveTree);
    console.log('');

    // Get the last block number and root from the asset curve tree.
    const blockNumber = await assetCurveTree.getLastBlockNumber();
    const assetTreeRoot = await assetCurveTree.getRoot(blockNumber);

    // Get the asset state and asset path.
    const assetState = await client.getAssetState(assetId); // Using the Rust client here to create the `AssetState` object from on-chain data.
    // The `AssetState` object can be recreated from the AssetDetails on-chain.
    // const assetDetails = api.query().confidentialAssets.dartAssetDetails(assetId);
    // const assetState = new AssetState(assetId, assetDetails.mediators, assetDetails.auditors); // The mediator/auditors encryption keys would need to be converted from the on-chain type.
    const assetLeafIndex = assetState.leafIndex();
    const assetPath = await assetCurveTree.getLeafPath(assetLeafIndex);

    // Build a settlement proof to transfer some asset from issuer to investor.
    console.log('Building settlement proof to transfer asset from issuer to investor...');

    // Create a settlement builder
    const settlementBuilder = new SettlementBuilder("Test memo", blockNumber, assetTreeRoot);

    // Add the asset path to the settlement builder
    settlementBuilder.addAssetPath(assetId, assetPath); // If the same asset is used in multiple legs, only need to add the asset path once.

    // Add a leg to transfer 250 units from issuer to investor 1
    const transferAmount = BigInt(250);
    const issuerLegBuilder = new LegBuilder(issuerPublicKeys, investor1PublicKeys, assetState, transferAmount);
    settlementBuilder.addLeg(issuerLegBuilder);

    // Add a leg to transfer 150 units from issuer to investor 2
    const transferAmount2 = BigInt(150);
    const issuerLegBuilder2 = new LegBuilder(issuerPublicKeys, investor2PublicKeys, assetState, transferAmount2);
    settlementBuilder.addLeg(issuerLegBuilder2);

    // Build the settlement proof
    const settlementProof = settlementBuilder.build();
    console.log('   ✓ Built settlement proof');
    console.log('   Settlement Proof Bytes Length:', settlementProof.toBytes().length);
    console.log('');

    // Create the settlement on-chain using the issuer signer.
    console.log('Creating settlement on-chain...');
    var settlementRef = null;
    try {
        const results = await issuer.createSettlement(settlementProof);
        settlementRef = results.settlementRef();
        console.log('   ✓ Settlement created with tx hash:', results.blockHash());
        console.log('');
    } catch (e) {
        console.error('   ✗ Error creating settlement:', e);
        process.exit(1);
    }

    // Retrieve and try to decrypt the settlement legs
    console.log('Retrieving and trying to decrypt settlement legs...');
    try {
        const settlement_legs = await client.getSettlementLegs(settlementRef);
        console.log('   ✓ Retrieved settlement with', settlement_legs.legCount(), 'legs');

        // Try to decrypt legs with issuer keys
        console.log('   Trying to decrypt legs with issuer keys...');
        const decrypted_legs_issuer = settlement_legs.tryDecrypt(issuerKeys);
        for (let i = 0; i < decrypted_legs_issuer.legCount(); i++) {
            const leg = decrypted_legs_issuer.getLeg(i);
            if (leg) {
                console.log(`   ✓ Decrypted leg ${i}:`);
                console.log('     Sender Public Key:', leg.sender.toJson());
                console.log('     Receiver Public Key:', leg.receiver.toJson());
                console.log('     Asset ID:', leg.assetId);
                console.log('     Amount:', leg.amount.toString());
            } else {
                console.log(`   ✗ Could not decrypt leg ${i}`);
            }
        }

        // Try to decrypt legs with investor 1
        console.log('   Trying to decrypt legs with investor 1...');
        const decrypted_legs_investor = settlement_legs.tryDecrypt(investor1Keys);
        for (let i = 0; i < decrypted_legs_investor.legCount(); i++) {
            const leg = decrypted_legs_investor.getLeg(i);
            if (leg) {
                console.log(`   ✓ Decrypted leg ${i}:`);
                console.log('     Sender Public Key:', leg.sender.toJson());
                console.log('     Receiver Public Key:', leg.receiver.toJson());
                console.log('     Asset ID:', leg.assetId);
                console.log('     Amount:', leg.amount.toString());
            } else {
                console.log(`   ✗ Could not decrypt leg ${i}`);
            }
        }
        console.log('');

        // Try to decrypt legs with investor 2
        console.log('   Trying to decrypt legs with investor 2...');
        const decrypted_legs_investor2 = settlement_legs.tryDecrypt(investor2Keys);
        for (let i = 0; i < decrypted_legs_investor2.legCount(); i++) {
            const leg = decrypted_legs_investor2.getLeg(i);
            if (leg) {
                console.log(`   ✓ Decrypted leg ${i}:`);
                console.log('     Sender Public Key:', leg.sender.toJson());
                console.log('     Receiver Public Key:', leg.receiver.toJson());
                console.log('     Asset ID:', leg.assetId);
                console.log('     Amount:', leg.amount.toString());
            } else {
                console.log(`   ✗ Could not decrypt leg ${i}`);
            }
        }
        console.log('');

        // Try to decrypt legs with mediator encryption key.
        console.log('   Trying to decrypt legs with mediator encryption key...');
        const decrypted_legs_mediator = settlement_legs.tryDecryptAsMediatorOrAuditor(mediatorEncryptionKey);
        for (let i = 0; i < decrypted_legs_mediator.legCount(); i++) {
            const leg = decrypted_legs_mediator.getLeg(i);
            if (leg) {
                console.log(`   ✓ Decrypted leg ${i}:`);
                console.log('     Sender Public Key:', leg.sender.toJson());
                console.log('     Receiver Public Key:', leg.receiver.toJson());
                console.log('     Asset ID:', leg.assetId);
                console.log('     Amount:', leg.amount.toString());
            } else {
                console.log(`   ✗ Could not decrypt leg ${i}`);
            }
        }
        console.log('');
    } catch (e) {
        console.error('   ✗ Error retrieving or decrypting settlement:', e);
        process.exit(1);
    }

    console.log('=== Example Complete ===');
    process.exit(0);
}

main();
