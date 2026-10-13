import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { groth16 } from "snarkjs";
import { validInput } from "./lib.mjs";

const wasm = "build/circuit/credential-v2_js/credential-v2.wasm";
const zkey = "build/keys/credential-v2_final.zkey";
const vkey = JSON.parse(await readFile("build/keys/verification_key.json", "utf8"));
const input = await validInput();
const startProof = performance.now();
const { proof, publicSignals } = await groth16.fullProve(input, wasm, zkey);
const proofMs = performance.now() - startProof;
const startVerify = performance.now();
const valid = await groth16.verify(vkey, publicSignals, proof);
const verifyMs = performance.now() - startVerify;
console.log(JSON.stringify({ valid, constraintsProfile: "credential-v2", proofMs, verifyMs,
  proofJsonBytes: Buffer.byteLength(JSON.stringify(proof)), publicSignalCount: publicSignals.length }, null, 2));
process.exit(valid ? 0 : 1);
