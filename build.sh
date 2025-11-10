#!/bin/bash
set -e

echo "Building WASM package for web..."
wasm-pack build --target web --out-dir pkg-web --scope polymesh

echo "Building WASM package for Node.js..."
wasm-pack build --target nodejs --out-dir pkg-node --scope polymesh

echo "Building WASM package for bundlers..."
wasm-pack build --target bundler --out-dir pkg --scope polymesh

echo "Build complete!"
echo "- Web package: pkg-web/"
echo "- Node.js package: pkg-node/"
echo "- Bundler package: pkg/"
