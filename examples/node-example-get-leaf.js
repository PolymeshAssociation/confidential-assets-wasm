// Node.js example for using Polymesh DART WASM
// Run with: node examples/node-example.js

//const WebSocket = require('ws');
Object.assign(global, { WebSocket: require('ws') });

const {
    PolymeshClient,
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
    const assetLeafPath = await assetCurveTree.getLeafPathAndRoot(leaf);

    console.log('=== Example Complete ===');
    process.exit(0);
}

main();
