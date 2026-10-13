import { groth16 } from "snarkjs";
import { deriveRequestBinding, deriveSessionScope } from "./binding.mjs";

export const PUBLIC_SIGNAL_COUNT = 6;

export class CredentialVerifier {
  constructor({ verificationKey, verifierId, roots, skills, now = Date.now }) {
    this.verificationKey = verificationKey;
    this.verifierId = verifierId;
    this.roots = new Set(roots.map(String));
    this.skills = new Map(skills.map((skill) => [skill.id, String(skill.index)]));
    this.now = now;
    this.challenges = new Map();
  }

  addChallenge(challenge) {
    if (this.challenges.has(challenge.id)) throw new Error("duplicate challengeId");
    this.challenges.set(challenge.id, { ...challenge, consumed: false });
  }

  async verify({ challengeId, proof, publicSignals }) {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) return { ok: false, reason: "challenge-unknown" };
    if (challenge.consumed || challenge.verifying) return { ok: false, reason: "challenge-consumed" };
    if (this.now() > challenge.expiresAt) return { ok: false, reason: "challenge-expired" };
    if (!Array.isArray(publicSignals) || publicSignals.length !== PUBLIC_SIGNAL_COUNT) {
      return { ok: false, reason: "presentation-malformed" };
    }

    const skillIndex = this.skills.get(challenge.skillId);
    if (skillIndex === undefined) return { ok: false, reason: "scope-map-unknown" };
    const sessionScope = deriveSessionScope({
      verifierId: this.verifierId,
      scopeName: challenge.scopeName,
      scopeValue: challenge.scopeValue,
    });
    const requestBinding = deriveRequestBinding({
      verifierId: this.verifierId,
      challengeNonce: challenge.nonce,
      skillId: challenge.skillId,
      requestDigest: challenge.requestDigest,
    });
    const expected = [String(challenge.issuerRoot), skillIndex, sessionScope, requestBinding];
    if (!this.roots.has(expected[0])) return { ok: false, reason: "root-untrusted" };
    for (let i = 0; i < expected.length; i++) {
      if (String(publicSignals[i + 2]) !== expected[i]) {
        return { ok: false, reason: "public-input-mismatch" };
      }
    }
    challenge.verifying = true;
    let valid;
    try {
      valid = await groth16.verify(this.verificationKey, publicSignals, proof);
    } finally {
      challenge.verifying = false;
    }
    if (!valid) return { ok: false, reason: "proof-invalid" };
    challenge.consumed = true;
    return { ok: true, nullifier: publicSignals[0], requestTag: publicSignals[1] };
  }
}
