#!/bin/bash
set -e

echo "Building WASM package with Rust client for web..."
wasm-pack build --release --target web --out-dir pkg-web --scope polymesh --features polymesh-client

echo "Building WASM package with Rust client for Node.js..."
wasm-pack build --release --target nodejs --out-dir pkg-node --scope polymesh --features polymesh-client

echo "Building WASM package with Rust client for bundlers..."
wasm-pack build --release --target bundler --out-dir pkg --scope polymesh --features polymesh-client

echo "Build complete!"
echo "- Web package: pkg-web/"
echo "- Node.js package: pkg-node/"
echo "- Bundler package: pkg/"
