#!/usr/bin/env bash
set -euo pipefail

echo "WARNING: this single-contributor setup is for development only."
test -f build/circuit/credential-v2.r1cs || npm run build:circuit
mkdir -p build/keys
npx snarkjs powersoftau new bn128 14 build/keys/pot14_0000.ptau -v
npx snarkjs powersoftau contribute build/keys/pot14_0000.ptau build/keys/pot14_0001.ptau \
  --name="zk-A2A development contribution" -e="zk-a2a-development-only"
npx snarkjs powersoftau prepare phase2 build/keys/pot14_0001.ptau build/keys/pot14_final.ptau -v
npx snarkjs groth16 setup build/circuit/credential-v2.r1cs build/keys/pot14_final.ptau build/keys/credential-v2_0000.zkey
npx snarkjs zkey contribute build/keys/credential-v2_0000.zkey build/keys/credential-v2_final.zkey \
  --name="zk-A2A development contribution" -e="zk-a2a-credential-v2-development-only"
npx snarkjs zkey export verificationkey build/keys/credential-v2_final.zkey build/keys/verification_key.json
