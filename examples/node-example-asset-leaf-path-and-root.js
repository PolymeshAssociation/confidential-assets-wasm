// Node.js example for using Polymesh DART WASM
// Run with: node examples/node-example.js

//const WebSocket = require('ws');
Object.assign(global, { WebSocket: require('ws') });

const {
    PolymeshClient,
    AssetLeafPathBuilder
} = require('../pkg-node/polymesh_dart_wasm.js');

console.log('=== Polymesh DART WASM Node.js Example ===\n');

async function main() {
    const client = await PolymeshClient.connect("ws://localhost:9944");
    console.log('   ✓ Connected to Polymesh node');
    console.log('   Client:', client);
    console.log('');

    // Get the asset curve tree.
    console.log('Getting asset curve tree...');
    const assetCurveTree = await client.getAssetCurveTree();
    console.log('   ✓ Retrieved asset curve tree');
    console.log('   Asset Curve Tree:', assetCurveTree);
    console.log('');

    const leaf = 0n;
    console.log('Get the path to the asset leaf: ', leaf);
    const assetLeafPathAndRoot = await assetCurveTree.getLeafPathAndRoot(leaf);
    const blockNumber = assetLeafPathAndRoot.getBlockNumber();

    // Test asset leaf path builder
    const assetLeafPathBuilder = new AssetLeafPathBuilder(leaf, 4, blockNumber);
    console.log('   ✓ Created asset leaf path builder: ', assetLeafPathBuilder);

    // Query the chain for the required leaves.
    const leafIndices = assetLeafPathBuilder.getLeafIndices();
    for (let i = 0; i < leafIndices.length; i++) {
        const index = leafIndices[i];
        console.log(`   leaf index ${i}: ${index}`);
        const leaf = await client.getAssetLeaf(index, blockNumber);
        console.log(`      got leaf: ${leaf}`);
        // Add the leaf to the path builder.
        assetLeafPathBuilder.setLeaf(index, leaf);
    }

    // Query the chain for the required inner nodes.
    const nodeLocations = assetLeafPathBuilder.getNodeLocations();
    for (let i = 0; i < nodeLocations.length; i++) {
        const location = nodeLocations[i];
        console.log(`   node ${i} at location ${location}`);
        const node = await client.getAssetInnerNode(location, blockNumber);
        console.log(`      got node: ${node}`);
        // Add the node to the path builder.
        assetLeafPathBuilder.setNodeAtIndex(i, node);
    }

    // Query the chain for the asset tree root.
    console.log('Getting asset tree root at block number ', blockNumber, '...');
    const assetTreeRoot = await client.getAssetTreeRoot(blockNumber);
    console.log('   ✓ Retrieved asset tree root: ', assetTreeRoot);
    console.log('');
    // Add the root to the path builder.
    assetLeafPathBuilder.setRoot(assetTreeRoot);
    console.log('   ✓ Set asset tree root in builder');

    // Build the path.
    console.log('Building the asset leaf path...');
    const assetLeafPath2 = assetLeafPathBuilder.buildLeafPath();
    console.log('   ✓ Set leaves and nodes in builder');

    // Build the path with root.
    console.log('Building the asset leaf path with root...');
    const assetLeafPathAndRoot3 = assetLeafPathBuilder.buildLeafPathWithRoot();
    console.log('   ✓ Built asset leaf path with root');

    // Check that the built path matches the retrieved path.
    console.log('Checking that the built path matches the retrieved path...');
    const bytes1 = assetLeafPathAndRoot.toBytes();
    const bytes3 = assetLeafPathAndRoot3.toBytes();
    if (bytes1.length !== bytes3.length) {
        throw new Error('Built path does not match retrieved path (length mismatch)');
    }
    for (let i = 0; i < bytes1.length; i++) {
        if (bytes1[i] !== bytes3[i]) {
            throw new Error('Built path does not match retrieved path (byte mismatch)');
        }
    }
    console.log('   ✓ Built path matches retrieved path');

    console.log('=== Example Complete ===');
    process.exit(0);
}

main();
