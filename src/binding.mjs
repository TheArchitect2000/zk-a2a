import { createHash } from "node:crypto";

const utf8 = (value) => Buffer.from(value, "utf8");

function framed(value) {
  const bytes = Buffer.isBuffer(value) ? value : utf8(value);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return Buffer.concat([length, bytes]);
}

function truncatedField(parts) {
  const digest = createHash("sha256").update(Buffer.concat(parts)).digest();
  digest[0] = 0;
  return BigInt(`0x${digest.toString("hex")}`).toString();
}

export function deriveSessionScope({ verifierId, scopeName, scopeValue }) {
  return truncatedField([
    utf8("zk-a2a/v1/session-scope"), Buffer.from([0]),
    framed(verifierId), framed(scopeName), framed(scopeValue),
  ]);
}

export function deriveRequestBinding({ verifierId, challengeNonce, skillId, requestDigest }) {
  const nonce = Buffer.isBuffer(challengeNonce)
    ? challengeNonce
    : Buffer.from(challengeNonce, "base64url");
  const digest = Buffer.isBuffer(requestDigest)
    ? requestDigest
    : Buffer.from(requestDigest, "hex");
  if (nonce.length < 16) throw new Error("challengeNonce must contain at least 16 bytes");
  if (digest.length !== 32) throw new Error("requestDigest must contain exactly 32 bytes");
  return truncatedField([
    utf8("zk-a2a/v1/binding"), Buffer.from([0]), framed(verifierId),
    framed(nonce), framed(skillId), digest,
  ]);
}

export function sha256(data) {
  return createHash("sha256").update(data).digest();
}
