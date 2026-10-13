import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { groth16, wtns } from "snarkjs";
import { validInput } from "../scripts/lib.mjs";
import { deriveRequestBinding, deriveSessionScope, sha256 } from "../src/binding.mjs";
import { CredentialVerifier } from "../src/verifier.mjs";

const wasm = "build/circuit/credential-v2_js/credential-v2.wasm";
const zkey = "build/keys/credential-v2_final.zkey";
const vkey = JSON.parse(await readFile("build/keys/verification_key.json", "utf8"));

test("valid credential proves and verifies", async () => {
  const { proof, publicSignals } = await groth16.fullProve(await validInput(), wasm, zkey);
  assert.equal(await groth16.verify(vkey, publicSignals, proof), true);
  assert.equal(publicSignals.length, 6);
});

test("proof is bound to root, skill, scope, and request", async () => {
  const { proof, publicSignals } = await groth16.fullProve(await validInput(), wasm, zkey);
  for (const index of [2, 3, 4, 5]) {
    const changed = publicSignals.slice();
    changed[index] = (BigInt(changed[index]) + 1n).toString();
    assert.equal(await groth16.verify(vkey, changed, proof), false, `public signal ${index}`);
  }
});

test("unauthorized and out-of-range skills cannot produce a witness", async () => {
  for (const skillIndex of ["2", "64"]) {
    await assert.rejects(wtns.calculate(await validInput({ skillIndex }), wasm, "/tmp/zk-a2a-invalid.wtns"));
  }
});

test("Merkle path selectors must be boolean", async () => {
  const input = await validInput();
  input.pathIndices[0] = 2;
  await assert.rejects(wtns.calculate(input, wasm, "/tmp/zk-a2a-invalid-path.wtns"));
});

test("same scope keeps nullifier; fresh request changes requestTag", async () => {
  const first = await groth16.fullProve(await validInput({ requestBinding: "10" }), wasm, zkey);
  const second = await groth16.fullProve(await validInput({ requestBinding: "11" }), wasm, zkey);
  assert.equal(first.publicSignals[0], second.publicSignals[0]);
  assert.notEqual(first.publicSignals[1], second.publicSignals[1]);
});

test("verifier reconstructs inputs and consumes a successful challenge", async () => {
  const verifierId = "https://supplier.example/.well-known/agent-card.json";
  const nonce = Buffer.alloc(16, 7);
  const requestDigest = sha256("canonical opening message");
  const sessionScope = deriveSessionScope({ verifierId, scopeName: "context", scopeValue: "ctx-123" });
  const requestBinding = deriveRequestBinding({ verifierId, challengeNonce: nonce, skillId: "quote.request", requestDigest });
  const input = await validInput({ sessionScope, requestBinding });
  const { proof, publicSignals } = await groth16.fullProve(input, wasm, zkey);
  const verifier = new CredentialVerifier({
    verificationKey: vkey, verifierId, roots: [input.issuerRoot],
    skills: [{ id: "quote.request", index: 3 }], now: () => 1000,
  });
  verifier.addChallenge({ id: "challenge-1", nonce, skillId: "quote.request",
    issuerRoot: input.issuerRoot, scopeName: "context", scopeValue: "ctx-123",
    requestDigest, expiresAt: 2000 });
  assert.equal((await verifier.verify({ challengeId: "challenge-1", proof, publicSignals })).ok, true);
  assert.deepEqual(await verifier.verify({ challengeId: "challenge-1", proof, publicSignals }),
    { ok: false, reason: "challenge-consumed" });
});
