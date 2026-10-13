import test from "node:test";
import assert from "node:assert/strict";
import { deriveRequestBinding, deriveSessionScope, sha256 } from "../src/binding.mjs";

test("session scope is deterministic and verifier-bound", () => {
  const input = { verifierId: "https://supplier.example/.well-known/agent-card.json", scopeName: "context", scopeValue: "ctx-123" };
  assert.equal(deriveSessionScope(input), deriveSessionScope(input));
  assert.notEqual(deriveSessionScope(input), deriveSessionScope({ ...input, verifierId: "https://other.example/.well-known/agent-card.json" }));
});

test("request binding changes with challenge, skill, or request", () => {
  const base = {
    verifierId: "https://supplier.example/.well-known/agent-card.json",
    challengeNonce: Buffer.alloc(16, 1), skillId: "quote.request",
    requestDigest: sha256("message one"),
  };
  const value = deriveRequestBinding(base);
  assert.notEqual(value, deriveRequestBinding({ ...base, challengeNonce: Buffer.alloc(16, 2) }));
  assert.notEqual(value, deriveRequestBinding({ ...base, skillId: "order.commit" }));
  assert.notEqual(value, deriveRequestBinding({ ...base, requestDigest: sha256("message two") }));
});

test("request binding rejects malformed challenge and digest", () => {
  const base = { verifierId: "https://supplier.example", skillId: "quote.request" };
  assert.throws(() => deriveRequestBinding({ ...base, challengeNonce: Buffer.alloc(15), requestDigest: Buffer.alloc(32) }));
  assert.throws(() => deriveRequestBinding({ ...base, challengeNonce: Buffer.alloc(16), requestDigest: Buffer.alloc(31) }));
});
