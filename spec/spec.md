# zk-A2A: Zero-Knowledge Credential Presentation for the Agent2Agent Protocol

**Status:** EXPERIMENTAL DRAFT — an independent, unofficial extension profile, not reviewed or adopted by the A2A project. Published for review; may change or be withdrawn.

**Version** 1.0.0-draft · **URI** `https://w3id.org/zk-a2a/v1` · **Author** Gholamreza Ramezan · **License** Apache-2.0 · BCP 14 [RFC2119][RFC8174] keywords apply only in capitals.

A profile: A2A bindings and defaults for constructions that already exist — anonymous credentials, accumulator revocation, scope-bound nullifiers, issuer hiding (§14). The contribution is the binding to A2A's object model and extension mechanics. Threat model and rejected alternatives: **[RATIONALE]**.

## 1. What it does

A client agent shows a server agent it has never met that it holds a valid, unrevoked credential whose scope covers the `AgentSkill` it invokes, without disclosing its identity, its credential, its issuer, or any scope bit beyond that skill. Presentations by one holder to one verifier are unlinkable across sessions and non-replayable within one.

Carriage uses only existing structures — an `AgentExtension`, the `A2A-Extensions` header and its echo, profile fields in `Message` and `Task` `metadata` keyed by the extension URI, and the proof in a `data` `Part` — so the profile defines no RPC method, message type, `TaskState`, or enum value. Its privacy properties are conditional: they hold against a verifier that sees only the presentation, where the candidate population is adequate (§11), the channel is confidential, and the rest of the request does not identify the caller.

## 2. Scope and non-goals

**For** discovery and quoting between organizations: catalog queries, availability checks, quotations, eligibility pre-checks — skills where the server's exposure is the information in its response, not an obligation it incurs. A procurement agent queries forty suppliers for a quote; under a bearer credential all forty learn which buyer is sourcing which part, and two colluding suppliers confirm the same buyer approached both. The caller proves scope here, then authenticates under the skill's `security_requirements` when it orders.

**Not for** settlement, regulated audit trails, post-hoc accountability, assurance about agent behavior, server attestation, or network-layer anonymity.

- A verifier MUST NOT accept a presentation as the sole authorization for an operation that moves funds, creates a payment obligation, executes an order, or otherwise binds a party to a financial outcome; such skills MUST require a named scheme satisfying their `security_requirements`.

## 3. Evaluate these first

`HTTPAuthSecurityScheme.scheme` points into the IANA HTTP Authentication Schemes registry, where RFC 9577 registers `PrivateToken`: A2A expresses non-identifying, unlinkable authorization today, in an unmodified Agent Card, without this profile, and a deployment needing only that SHOULD evaluate Privacy Pass first. `a2aproject/experimental-ext-oid4vp-auth` is A2A's general-purpose credential-presentation extension and the appropriate default; it uses the same `TASK_STATE_AUTH_REQUIRED` turn and metadata carriage this profile follows, and a deployment MAY declare both, per skill.

For plain unlinkable attribute presentation, BBS is faster than Groth16 (~1–2 ms) and needs no trusted setup, and deployments SHOULD NOT operate the Groth16 profile where the statement reduces to selective disclosure that BBS expresses. Groth16 earns its per-circuit trusted setup only for a predicate over committed state: accumulator membership against a changing root, an in-circuit nullifier from a secret the verifier never sees, and bitmap indexing revealing one bit — jointly, in one proof.

| Mechanism | Unlinkable | Hides issuer | Scope predicate | Setup |
|---|---|---|---|---|
| Privacy Pass `PrivateToken` | Yes | No | No | No |
| `experimental-ext-oid4vp-auth`, SD-JWT | Per format | No | Disclosure only | No |
| BBS / Data Integrity BBS | Yes | No | Selective disclosure | No |
| zk-A2A Groth16 | Yes | Within an anchor | Yes | Per circuit |

## 4. Objects and encoding

**Scope bitmap** — one bit per skill index, committed in the credential leaf; the statement proves `scopeBitmap[skillIndex] == 1` and discloses only that bit. **Nullifier** — derived in-circuit from the credential secret and a scope value, published as a public output. **Anchor** — verifier configuration committing to a set of credentials or issuer keys.

`#credential` proves inclusion under an anchored root, the requested skill's bit set, and scope- and request-bound holder tags, hiding the issuer within the anchor; `#scope-disclosure` proves a signature by one of an anchored key list and names the issuer. A challenge solicits one statement. Public signals for `zk-a2a/credential/v2#bn254-poseidon-d20` are `[nullifier, requestTag, issuerRoot, skillIndex, sessionScope, requestBinding]`: the first two are outputs and MAY be taken from the presentation; the other four are verifier-sourced inputs (§6.4).

- Any integer that may exceed 2^53 MUST be a string, since `Struct` and `Value` hold numbers as doubles. Field elements are decimal strings, byte strings unpadded base64url, timestamps RFC 3339.
- Consumers MUST ignore unrecognized keys rather than reject the object.
- Profile fields MUST live in `metadata` under the exact extension URI, compared by code-point equality, with a `kind` discriminator; the `data` `Part` is reserved for the presentation.

## 5. Extension declaration

One `AgentExtension` whose `uri` is the extension URI, with configuration in `params`, named per the `a2a-sdk` 1.1.2 protobuf JSON mapping.

- A card carrying two or more entries with this URI MUST be read as carrying no declaration, and a consumer MUST NOT select one.
- `roles`, `statements`, `proofSystems`, `trustAnchors`, `bindingProfile`, `challenge`, and `skillScopes` MUST be retrievable without client authentication, never moved to the extended Agent Card.
- Any change affecting the verification key — arithmetization, `treeDepth`, `maxSkills`, hash, statement, ceremony — MUST produce a new `parameterSetId`. Peers sharing an `id` but not a `parameterSetId` are disjoint.

`proofSystems` carries `id`, `parameterSetId`, `hash`, `setup` in preference order; `trustAnchors` carries `anchorId`, `role`, tree parameters, the scope-map pointers, `populationLowerBound`, and the §9 freshness parameters; `challenge` carries `nonceBytes` ≥ 16, `ttlSeconds`, `maxAttempts`; `skillScopes` maps each gated skill to `anchorId`, `scopeNamespace`, `index`, `mode`. Optional: `verificationKeys` with pinned digests, `nullifierScope`, `nullifierConsistency`.

**Scope maps.** Index assignment is authoritative at the issuer, never at the verifier.

- An issuer MUST publish a scope map binding each index to a stable capability identifier, name it by `scopeMapUri` and `scopeMapHash` in every root statement, and keep it append-only, never reusing an index.
- Before proving, a prover MUST resolve that map, verify it against the pinned digest, and confirm the verifier's `(scopeNamespace, capabilityUri, index)` triple denotes the scope its credential authorizes, refusing with `scope-map-mismatch` otherwise. Unchecked, a verifier can map `booking.commit` to an index meaning read-only quoting at the issuer, and every quote-only holder proves what it reads as authorization to commit.
- A verifier MUST resolve the gated `AgentSkill.id` through the map named in the root statement it verifies against, pinned by its own `params` digest, rejecting an absent, unpinned, or mismatched map (`scope-map-unknown`) and an index differing from `skillIndex` (`skill-index-mismatch`).
- `substitute` means a presentation grants access, `augment` that it is required alongside the skill's declared requirements. A verifier SHOULD populate a gated skill's `security_requirements` explicitly, and SHOULD NOT treat an `augment` skill as anonymous where those requirements identify the caller.
- Scope vocabularies SHOULD stay coarse, since colluding verifiers accumulate bits per holder.

## 6. Negotiation, challenge, presentation

### 6.1 Activation

The client selects a statement, proof system, and anchor common to both cards. Echo means activated, not verified.

- A client MUST send the URI in the `A2A-Extensions` header and in `Message.extensions` on every request and message carrying or expecting profile data, never inferring activation from an earlier request; a server MUST NOT activate or echo the URI for a request that did not list it (`activation-mismatch`), and MUST ignore, without verifying, a presentation on a non-activated exchange (`extension-not-activated`).
- A client MUST NOT send a presentation before the echo, since that consumes its nullifier regardless, and MUST NOT fall back to an identifying scheme automatically; fallback requires explicit per-verifier configuration, or anyone who can strip a header has a deanonymization oracle.
- An implementation MUST report to its caller whether an exchange was anonymous or identified.

### 6.2 Opening message

The challenge takes its own round trip because at first contact every bindable value is prover-chosen. The opening message carries `{"kind": "intent", "skillId", "statements"}` in `Message.metadata`.

- A client MUST NOT include a presentation in the opening message, MUST NOT set `context_id` — the server assigns the context, which is what makes it a verifier-controlled scope value — and MUST name the skill by `AgentSkill.id` as published.

### 6.3 Challenge

Carried in `Task.status.message.metadata` under the extension URI at `TASK_STATE_AUTH_REQUIRED` (`Task.metadata` where there is no status message), never in a `Part`. Mandatory keys: `kind: "challenge"`, `challengeId`, `challengeNonce`, `verifierId`, `bindingProfile`, `statement`, `proofSystems`, `parameterSetIds`, `skillId`, `skillIndex`, `scopeProfile`, `scopeValue`, `acceptedRoots` (`{anchorId, root, epoch, iat, ttl}`), `expiresAt`, `maxAttempts`.

- `challengeNonce` MUST come from a CSPRNG with ≥128 bits of entropy, and MUST NOT be derived from a counter, timestamp, request hash, the client's `message_id`, or any value the prover observes or influences.
- A challenge MUST be single-use, bound to the recorded `context_id` and `task_id`, and expired against the verifier's own clock. TTL SHOULD NOT exceed 600 s (120 RECOMMENDED) and `maxAttempts` SHOULD NOT exceed 5 (default 1).

### 6.4 Presentation and verifier procedure

Mandatory presentation keys: `profile`, `kind: "presentation"`, `challengeId`, `statement`, `proofSystem`, `parameterSetId`, `anchorId`, `rootEpoch`, `proof`, `outputs`. `anchorId` and `rootEpoch` select from `acceptedRoots`; a root value is never supplied. For `groth16-bn254` the proof is 128 bytes, compressed `A` ‖ `B` ‖ `C` (32, 64, 32).

- The presentation MUST travel as a `data` `Part` on the same task with `media_type` `application/zk-a2a+json`, and a message MUST contain exactly one part parsing as a presentation (`attestation-malformed`).
- A verifier MUST reject a decoded proof length other than the profile's before decompression, and points off the curve or outside the prime-order subgroup, and MUST NOT use proof bytes as a deduplication or replay key, since proofs are re-randomizable.
- A verifier MUST perform these steps in order, with no partial acceptance: (1) check activation and envelope — size limit before parsing, one presentation part, public-signal count matching the parameter set; (2) resolve `challengeId` in its own store, scoped to `task_id` and `context_id`, rejecting unknown, expired, consumed, wrong-context, over-attempt; (3) resolve the verification key from local configuration against a pinned digest; (4) reconstruct the public inputs (`issuerRoot`, `skillIndex`, `sessionScope` §7, `requestBinding` §8); (5) compare each public signal byte for byte; (6) apply §9 freshness; (7) verify; (8) record `(scopeValue, nullifier)` atomically with acceptance, on acceptance only, and consume the challenge.
- At steps 3 and 4 a verifier MUST take the key and every public input from its own configuration and stored challenge state, never from the presentation or another prover-controlled surface: a prover that supplies either proves a statement the verifier did not ask about (`root-untrusted`).
- A verifier MUST NOT accept a presentation not bound to a challenge it issued in the same task, and MUST NOT treat an unsolicited presentation as authorization.
- Before presenting, a prover MUST check `verifierId` against the card it fetched and the authenticated peer (`audience-mismatch`), `scopeValue` against the `Task`, and the §5 scope map.

Accepted → `TASK_STATE_WORKING`/`COMPLETED`; retryable rejection → `AUTH_REQUIRED` with a new challenge; terminal refusal → `REJECTED`; verifier fault → `FAILED`. Implementations MUST NOT infer task states beyond these.

## 7. Nullifier scope

```
sessionScope = trunc248( SHA-256( "zk-a2a/v1/session-scope" || 0x00
                                  || B(verifier_id) || B(scopeName) || B(scopeValue) ) )
nullifier = H(secret, sessionScope)
requestTag = H(secret, requestBinding)    ; H = circomlib Poseidon(2) over BN254 Fr
```

`scopeName = "context"` with `scopeValue` = UTF-8 bytes of `Task.context_id`; `"task"` with `Task.id` gives the task profile. `verifier_id` sits inside the scope so two providers seeing one `context_id` do not observe equal nullifiers for one holder.

- Implementations MUST support, and use unless the card declares otherwise, this verifier-bound context scope.
- A verifier MUST recompute `sessionScope` from its own `verifier_id` and recorded scope value, never a client-asserted one. `scopeValue` MUST be verifier-generated with ≥128 bits of entropy and MUST NOT be reused.
- `sessionScope` and `requestBinding` MUST be separate public inputs; a verifier MUST NOT use nullifier uniqueness as its replay check, nor `requestBinding` as its rate-limit key.
- A verifier MUST NOT reject a presentation solely because its nullifier repeats within one `sessionScope`. Repetition is the steady state: it is how a verifier attaches quotes and holds to a counterparty it has not identified. Freshness comes from the challenge and `requestBinding`.
- A verifier MUST NOT export or publish nullifiers, or place them in `Artifact` contents, `Message` parts, or any output another agent sees, and MUST delete entries by the declared scope bound after `firstSeen`.

## 8. Transport binding

Binding is over A2A object-model values, not serialized bytes, which are not canonical across bindings. Profile `https://w3id.org/zk-a2a/v1#binding-1`:

```
requestBinding = trunc248( SHA-256( "zk-a2a/v1/binding" || 0x00 || B(verifier_id)
                                    || B(challengeNonce) || B(skill_id) || requestDigest ) )
requestDigest  = SHA-256( CME(M, op) )
trunc248(d)    = the 32-octet digest with its top octet set to 0x00, big-endian
B(x) = U64BE(len(x)) || x ; O(x) = 0x00 when unset, else 0x01 || B(x)

CME(M, op) = "zk-a2a/v1/cme" || 0x00 || 0x01 || B(op) || 0x02 || O(M.context_id)
 || 0x03 || O(M.task_id) || 0x04 || O(M.message_id) || 0x05 || U8(M.role)
 || 0x06 || U32BE(n) || PART(p_1) … PART(p_n) || 0x07 || U32BE(k) || B(u_1) … B(u_k)
 || 0x08 || O( JCS(M.metadata minus this profile's key) )
PART(p) = 0x10 || U8(kind) || O(p.media_type) || O(p.filename) || B(body) || O(JCS(p.metadata))
kind: 1 text · 2 raw · 3 url · 4 data (UTF-8 of JCS(value))
```

`challengeNonce` is the decoded octets, `requestDigest` a fixed 32 octets with no length prefix, `JCS` RFC 8785 over the proto3 JSON mapping. `p_1…p_n` are the parts in order, excluding the presentation part, since a proof cannot commit to itself; `u_1…u_k` are `Message.extensions` minus this URI, sorted; streaming binds the initiating `Message`.

- `requestBinding` MUST be a declared public input and MUST determine `requestTag = H(secret, requestBinding)` in-circuit. A different request therefore requires a fresh proof and produces a different request tag. Implementations SHOULD confirm the binding constraints in the emitted R1CS.
- `verifier_id` MUST be the absolute HTTPS well-known Agent Card URL the prover fetched, normalized per RFC 3986 §6.2.2–6.2.3, or `"jkt:"` plus the RFC 7638 thumbprint of the card-signing key under `verifierIdSource: "cardKeyThumbprint"`. A verifier reachable at several names MUST configure one canonical value; endpoints sharing a `verifier_id` are one linkage domain.
- `skill_id` MUST be the UTF-8 octets of `AgentSkill.id` as published, and a verifier MUST reject a `skillIndex` outside the bitmap length fixed by the verifying key.
- Implementations MUST bind the abstract operation identifier (`a2a.message.send`, `a2a.message.stream`), not a binding-specific method name. A custom binding MUST define activation carriage and echo, where the `Message` lives, and an `op` per operation.

## 9. Trust anchors and root freshness

- A verifier MUST NOT contact an issuer about a specific presentation: root and JWKS retrieval runs on a schedule, never triggered by a presentation or unknown `kid`, which would make the issuer an oracle.
- A verifier MUST hold its anchor set as local configuration, MUST NOT adopt an anchor a presentation names, and MUST NOT fetch a root, key list, or scope map from a presenter URL.

**Accumulator.** `leaf_i = Poseidon(secret_i, issuerId_i, scopeBitmap_i)` in a fixed-depth Poseidon Merkle tree; the other leaf inputs are low-entropy, so hiding rests on `secret` alone.

- The credential secret MUST be generated by the holder from a CSPRNG with ≥128 bits of entropy, MUST NOT be disclosed to the issuer — which receives only the leaf commitment — and MUST NOT be derived from identifying data or a counter.
- Revocation MUST replace the leaf with the empty-leaf value at its index; issuers MUST NOT compact or re-index the tree, and MUST publish per epoch, addressable by number, the `(index, newLeafValue)` pairs changed since the previous epoch, retained for `Δ_hard`.

**Root statements.** Reference encoding: a JWS-signed JWT, `typ: "zk-a2a-root+jwt"`.

- A verifier MUST NOT accept a bare root value as a trust anchor: a root is usable only as the `root` member of a signed statement validated against an anchored issuer key, carrying `profile`, `parameterSetId`, `issuerId`, `epoch`, `root`, `previousRoot`, the tree and scope-map parameters, `iat`, `ttl`, `exp`, and a resolvable `kid`.
- `epoch` MUST increase by one per publication, `previousRoot` MUST equal the root of `epoch − 1`, and an issuer MUST republish at every interval boundary whether or not the leaf set changed, since change-only publication lets timing disclose revocations.
- Two validly signed statements with one `iss` and `epoch` but different `root` MUST make the verifier reject both and use neither later (`root-equivocation`).

**Freshness.** `T_pub` = `publicationIntervalSeconds` (900 s); `ttl` = 4·`T_pub`; `Δ_v` = `maxRootAgeSeconds` (3600 s, SHOULD be ≥ 2·`T_pub` + `skew`); `Δ_hard` (86400 s); `skew` (60 s); `Δ_eff(R) = min(Δ_v, ttl(R))`; `age(R) = now − iat(R)`.

- `acceptedRoots` MUST be present, non-empty, and newest first; a verifier MUST NOT list a root it would refuse when sending, and MUST accept any root it listed for the life of the challenge even if it ages past `Δ_v`. Provers SHOULD prove against the oldest root in the window, so differing refresh cadences are indistinguishable.
- Each check gates the next: resolve the statement in the verifier's own cache, `anchorId`/`rootEpoch` being locators only (`root-unknown`); authenticate it against the anchored key (`root-signature-invalid`); match `parameterSetId`, `treeDepth`, `hash`, `scopeMapHash` to the pinned values (`root-parameter-mismatch`); check chaining, `iat` within `skew`, and the root recorded for this challenge (`root-untrusted`); accept if `age(R) ≤ Δ_eff(R)`, degrade up to `Δ_hard`, else `root-stale`.
- Degraded acceptance MUST be off by default, enabled per anchor by configuration, never silent, never authorizing an operation with a side effect, and disclosed with `root-degraded`.

## 10. Proof-system profiles

A conforming profile MUST specify: its identifiers; the credential commitment, membership relation, and nullifier construction with their domain separation; verification-key naming and digest pinning; setup and transcript publication; proof encoding and media type; measured performance; and the ordered public inputs and outputs with their byte encodings.

| | `groth16-bn254` | `bbs-2023` |
|---|---|---|
| Statement | `#credential` | `#scope-disclosure` |
| Parameters | BN254, Poseidon, depth 20, `maxSkills` 64 | BLS12-381, SHA-256 |
| Setup | per-circuit trusted | transparent |
| Proof | 128 bytes | larger, grows with undisclosed messages |
| Cost | 5,837 R1CS; current sample ~428 ms prove, ~7.2 ms verify | ~1–2 ms prove |
| Issuer hiding | within an anchor | not in v1 |

- A Groth16 deployment MUST run or adopt a multi-contributor phase-2 ceremony per circuit, publish an independently verifiable transcript, and MUST NOT run production on a single-contributor ceremony, including the reference implementation's. A transcript records contributions, not the destruction of a contributor's randomness, and a party retaining it can mint credentials undetectably.
- Any change to depth, `maxSkills`, hash, or statement MUST get a new phase-2 ceremony and a new `parameterSetId`; circuit parameters are not configuration. Provers SHOULD pin a verified CRS by digest.
- A BBS profile MUST supply a revocation mechanism and a per-session scope-bound pseudonym; per-verifier pseudonyms alone are constant for a `(prover, verifier)` pair and coarser than §7.

## 11. Privacy considerations

**The candidate set is adversary-computable.** A2A serves Agent Cards from an unauthenticated well-known URL, so a crawler can enumerate offline the agents that could have produced a presentation, partitioned by anchor, skill index, and epoch — the values the public signals disclose. Other channels leak more than the proof in most deployments: skill-scope granularity, timing, card-fetch patterns, the header echo, reason granularity, root cadence. Credentials are cloneable, so possession is what is proved; a malicious issuer can mint and, if it chose the secret, link everything; transport confidentiality and integrity remain necessary.

**Anonymity floor.** A prover SHOULD estimate the candidate-set size `k_est` for the exact scope tuple before emitting a presentation, and SHOULD NOT emit below its configured `k_floor`, resolved as the larger of the two declared floors. `k_floor` SHOULD be configurable and default to at least 50 — a deployability figure, not a security derivation, roughly 5.6 bits and orders of magnitude below the floors FIDO and Bitstring Status List adopted. A prover with no population evidence SHOULD refuse. This is a SHOULD, not a MUST with refusal behavior, because estimating `k` is itself unresolved (§13), and a requirement implementers cannot evaluate is one they ignore, which weakens every requirement beside it.

**Estimating `k`.** Three sources: a crawl over agents publishing `holderDeclaration`; an issuer-attested signed count of unrevoked leaves per skill index, best where holders publish nothing; a registry count, which its operator can inflate. Compute over the intersection of anchor root, skill index, and epoch, because the adversary intersects them; prefer the smaller count; invalidate on any change; keep `k_est` out of outward metadata. A verifier MAY refuse on the ground that the anonymity it provides is decorative (`anonymity-floor-unmet`). Below the floor, no long-lived bearer token crosses the wire and no stable revocation index is disclosed — both hold at any `k` — but unlinkability is vacuous at `k = 1`. A deployment not enforcing a floor SHOULD declare `anonymity.mode: "unlinkability-only"`, and SHOULD NOT ship that as its default.

## 12. Failure vocabulary

Canonical form: the lowercase token `zk-a2a/<slug>` in `TaskStatus.message.metadata` under the extension URI. The `ErrorInfo.reason` form is mechanical: strip the prefix, uppercase, hyphens to underscores.

| State, retry | Tokens |
|---|---|
| AUTH_REQUIRED, retry | `attestation-required`, `attestation-rejected` (RECOMMENDED outward default), `activation-mismatch`, `attestation-malformed`, `challenge-unknown`, `challenge-expired`, `challenge-consumed`, `binding-mismatch`, `scope-mismatch`, `root-unknown`, `root-untrusted`, `root-stale`, `proof-invalid`\* |
| AUTH_REQUIRED, no retry | `nullifier-replayed`\*, `scope-holder-changed`\* |
| REJECTED | `attestation-unsupported`, `extension-not-activated`, `parameter-set-unsupported`, `verification-key-unknown`, `skill-index-mismatch`, `root-parameter-mismatch` |
| FAILED | `scope-map-unknown`, `root-signature-invalid`, `root-unavailable`, `verifier-internal-error`; `root-equivocation` (no retry) |
| WORKING | `root-degraded` — accepted, provisional |

- A zk-A2A `ErrorInfo` MUST be appended after the core `a2a-protocol.org` `ErrorInfo`, never at index 0, since SDK clients stop at the leading detail without inspecting `domain`; zk-A2A reasons MUST NOT use that domain or carry variable data in the token.
- Implementations MUST emit only registered tokens, and receivers MUST tolerate unknown ones: unknown at `AUTH_REQUIRED` reads as `attestation-rejected`, elsewhere the state governs.
- A verifier MUST NOT include the nullifier, the scope value, a counter, or any other credential-derived value in a failure response or `ErrorInfo.metadata`, which the SDK serializes back unaltered. Tokens marked \* SHOULD go outward as `attestation-rejected` and be logged locally.

## 13. Conformance and open questions

Every normative statement above is written so one test exercises it. These five carry the security model and SHOULD be tested first.

1. **Inputs are verifier-sourced (§6.4).** A proof on an untrusted root or a different `skillIndex` is rejected, and the four inputs are caller-supplied arguments of the verification interface.
2. **The prover checks the scope map (§5).** A card contradicting the issuer's map yields `scope-map-mismatch` and no presentation.
3. **`requestBinding` is constrained (§8).** The emitted R1CS references the signal; a mutated value fails to verify.
4. **No issuer contact per presentation (§9).** An unknown root and `kid` produce zero outbound issuer requests.
5. **Holder-generated secret (§9).** The issuer receives only the leaf commitment.

**Open.** This profile has not been deployed, so no candidate-set size has been measured; whether populations reach even 50 holders per `(anchor, skill, epoch)` tuple is unknown, and if they do not, unlinkability-only mode is the honest configuration. The proof is fixed at 128 bytes in the order `A ‖ B ‖ C`, but the flag-bit convention is not pinned and differs between libraries; the reference implementation currently emits the toolchain's 726-byte JSON proof object. The revised circuit has 5,837 constraints, including the request-binding hash; its checked-in setup script performs a single-contributor development ceremony that MUST NOT be used for production. Parameter defaults come from analogy, not operational data. Cross-organizational trust sets, an epoch-scoped rate-limit nullifier, IANA registrations, the gRPC activation key, and the governance path — hence the extension URI — are in OPEN-ISSUES.md.

## 14. References

**Normative.** RFC 2119 / 8174; RFC 3986; RFC 7638; RFC 8615; RFC 8785 (JCS); the A2A protocol specification; `a2a-sdk` 1.1.2, source of the verified protobuf JSON mappings.

**Informative.** Camenisch–Lysyanskaya (EUROCRYPT 2001, CRYPTO 2002) and Idemix; Bobolz et al., CANS 2021, and the BBS issuer-hiding line following it; `draft-irtf-cfrg-bbs-signatures`, W3C Data Integrity BBS, `draft-irtf-cfrg-bbs-per-verifier-linkability`; OpenID4VP 1.0; SD-JWT with KB-JWT (RFC 9901); `experimental-ext-oid4vp-auth`; Privacy Pass (RFC 9576/9577/9578); Semaphore and RLN; `draft-ietf-oauth-status-list`; Groth (EUROCRYPT 2016); Circom and snarkjs; WebAuthn; EPID.

<!-- Word count: 3996 (wc -w, body only, excluding this comment). -->
