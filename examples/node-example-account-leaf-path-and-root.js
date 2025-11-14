// Node.js example for using Polymesh DART WASM
// Run with: node examples/node-example.js

//const WebSocket = require('ws');
Object.assign(global, { WebSocket: require('ws') });

const {
    PolymeshClient,
    AccountLeafPathBuilder
} = require('../pkg-node/polymesh_dart_wasm.js');

console.log('=== Polymesh DART WASM Node.js Example ===\n');

async function main() {
    const client = await PolymeshClient.connect("ws://localhost:9944");
    console.log('   ✓ Connected to Polymesh node');
    console.log('   Client:', client);
    console.log('');

    // Get the account curve tree.
    console.log('Getting account curve tree...');
    const accountCurveTree = await client.getAccountCurveTree();
    console.log('   ✓ Retrieved account curve tree');
    console.log('   Account Curve Tree:', accountCurveTree);
    console.log('');

    const leaf = 0n;
    console.log('Get the path to the account leaf: ', leaf);
    const accountLeafPathAndRoot = await accountCurveTree.getLeafPathAndRoot(leaf);
    const blockNumber = accountLeafPathAndRoot.getBlockNumber();

    // Test account leaf path builder
    const accountLeafPathBuilder = new AccountLeafPathBuilder(leaf, 4, blockNumber);
    console.log('   ✓ Created account leaf path builder: ', accountLeafPathBuilder);

    // Query the chain for the required leaves.
    const leafIndices = accountLeafPathBuilder.getLeafIndices();
    for (let i = 0; i < leafIndices.length; i++) {
        const index = leafIndices[i];
        console.log(`   leaf index ${i}: ${index}`);
        const leaf = await client.getAccountLeaf(index, blockNumber);
        console.log(`      got leaf: ${leaf}`);
        // Add the leaf to the path builder.
        accountLeafPathBuilder.setLeaf(index, leaf);
    }

    // Query the chain for the required inner nodes.
    const nodeLocations = accountLeafPathBuilder.getNodeLocations();
    for (let i = 0; i < nodeLocations.length; i++) {
        const location = nodeLocations[i];
        console.log(`   node ${i} at location ${location}`);
        const node = await client.getAccountInnerNode(location, blockNumber);
        console.log(`      got node: ${node}`);
        // Add the node to the path builder.
        accountLeafPathBuilder.setNodeAtIndex(i, node);
    }

    // Query the chain for the account tree root.
    console.log('Getting account tree root at block number ', blockNumber, '...');
    const accountTreeRoot = await client.getAccountTreeRoot(blockNumber);
    console.log('   ✓ Retrieved account tree root: ', accountTreeRoot);
    console.log('');
    // Add the root to the path builder.
    accountLeafPathBuilder.setRoot(accountTreeRoot);
    console.log('   ✓ Set account tree root in builder');

    // Build the path.
    console.log('Building the account leaf path...');
    const accountLeafPath2 = accountLeafPathBuilder.buildLeafPath();
    console.log('   ✓ Set leaves and nodes in builder');

    // Build the path with root.
    console.log('Building the account leaf path with root...');
    const accountLeafPathAndRoot3 = accountLeafPathBuilder.buildLeafPathWithRoot();
    console.log('   ✓ Built account leaf path with root');

    // Check that the built path matches the retrieved path.
    console.log('Checking that the built path matches the retrieved path...');
    const bytes1 = accountLeafPathAndRoot.toBytes();
    const bytes3 = accountLeafPathAndRoot3.toBytes();
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
