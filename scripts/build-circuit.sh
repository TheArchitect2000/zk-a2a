#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/circuit
circom circuits/credential-v2/credential-v2.circom \
  --r1cs --wasm --sym \
  -o build/circuit
npx snarkjs r1cs info build/circuit/credential-v2.r1cs
