import { readFile, writeFile, mkdir } from "node:fs/promises";
import * as snarkjs from "snarkjs";

const inputPath = process.argv[2] ?? "test-vectors/credential-v2-input.json";
const input = JSON.parse(await readFile(inputPath, "utf8"));
const wasm = "build/circuit/credential-v2_js/credential-v2.wasm";
const zkey = "build/keys/credential-v2_final.zkey";
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
await mkdir("build/proofs", { recursive: true });
await writeFile("build/proofs/proof.json", JSON.stringify(proof, null, 2) + "\n");
await writeFile("build/proofs/public.json", JSON.stringify(publicSignals, null, 2) + "\n");
const vkey = JSON.parse(await readFile("build/keys/verification_key.json", "utf8"));
if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) throw new Error("proof did not verify");
console.log("credential-v2 proof verified");
console.log(JSON.stringify(publicSignals));
process.exit(0);
