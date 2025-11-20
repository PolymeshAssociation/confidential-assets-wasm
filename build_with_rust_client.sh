#!/bin/bash
set -e

echo "Building WASM package with Rust client for web..."
wasm-pack build --release --features polymesh-client --target web --out-dir pkg-web --scope polymesh

echo "Building WASM package with Rust client for Node.js..."
wasm-pack build --release --features polymesh-client --target nodejs --out-dir pkg-node --scope polymesh

echo "Building WASM package with Rust client for bundlers..."
wasm-pack build --release --features polymesh-client --target bundler --out-dir pkg --scope polymesh

echo "Build complete!"
echo "- Web package: pkg-web/"
echo "- Node.js package: pkg-node/"
echo "- Bundler package: pkg/"
