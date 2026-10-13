# zk-A2A Design Notes

**Companion to:** `zk-a2a-v1.md` (zk-A2A: Zero-Knowledge Credential Presentation for the Agent2Agent Protocol)
**Status:** Non-normative. Nothing here is a requirement.
**Author:** Gholamreza Ramezan
**License:** Apache License 2.0

---

## Table of Contents

1. What this document is
2. Design constraints imposed by A2A
3. Nullifier scope
4. Anonymity sets and the enumerable population
5. Other linkage channels
6. Proof system selection
7. Prior art
8. Alternatives considered and rejected
9. Measured performance of the reference implementation

---

## 1. What this document is

### 1.1 Relationship to the specification

The specification says what an implementation does. This document says why, and what each choice costs. It carries the analysis that was cut from the specification so that a reviewer could read the specification in one sitting.

Nothing here is normative. There are no BCP 14 keywords in this document except where it quotes the requirement level the specification assigns to something, and those are marked as quotations. Where this document and the specification appear to disagree, the specification is correct and this document is stale.

Three companion files exist alongside it:

| File | Contents |
|---|---|
| `zk-a2a-v1.md` | The profile. Requirements, schemas, flows, failure registry, conformance. |
| `zk-a2a-design-notes.md` | This document. Rationale, threat analysis, alternatives, measurements. |
| `OPEN-ISSUES.md` | What the draft does not settle, with the four items most likely to change a deployment's decision listed first. |
| `REVIEW-NOTES.md` | Drafting provenance: the six independently written sections, where they disagreed, and how each disagreement was resolved. Of interest to the authors and to anyone who wants to reopen a decision rather than rediscover it. |

Reading order for a reviewer with limited time: §1.2 of this document, then §4. Section 4 is the part of the analysis that most changes what a deployment should conclude, and it is a negative result.

### 1.2 What already exists, stated before anything about what the profile adds

Three facts bound the value of this work. They belong at the front rather than in a related-work section, because a reader who stops after them has still reached the right decision for most deployments.

**Privacy Pass is already reachable from an unmodified Agent Card.** `HTTPAuthSecurityScheme.scheme` is a free-text pointer into the IANA HTTP Authentication Schemes registry. RFC 9577 registers `PrivateToken` in that registry. A2A can therefore express non-identifying, unlinkable authorization today, with no extension of any kind, using an IETF standard that has deployed implementations, needs no circuit, and needs no ceremony. A deployment whose requirement is "the caller holds an unlinkable token issued under a program I trust" should evaluate that path before reading further. What Privacy Pass does not carry is a predicate over the holder's authorization scope — redemption attests to a token type and an issuance program — and the token key identifier ties a redemption to a specific issuer.

**A2A already has a credential-presentation extension.** `a2aproject/experimental-ext-oid4vp-auth` specifies in-task authorization using OpenID for Verifiable Presentations, at URI `https://github.com/a2aproject/experimental-ext-oid4vp-auth/tree/main/v1`. It uses `TASK_STATE_AUTH_REQUIRED` for the round trip and carries its data in the message's `metadata` map keyed by the extension URI. zk-A2A follows both conventions rather than inventing alternatives. That extension is the general-purpose credential-presentation extension for A2A and the appropriate default. zk-A2A is narrower: it is for the case where the verifier's requirement is a predicate rather than a disclosure, and where issuer hiding and cross-verifier unlinkability are actual requirements. zk-A2A does not replace it or deprecate it, and a deployment needing both can declare both and select per skill.

**BBS is faster than Groth16 and needs no ceremony.** For plain unlinkable attribute presentation, BBS proof generation is on the order of 1–2 ms against roughly 200 ms for the reference Groth16 circuit, and it requires no trusted setup, which removes every deployment obligation in §6.3 below. Choosing Groth16 for a workload BBS covers costs roughly two orders of magnitude in prover time and adds a per-circuit ceremony for no gain. Groth16 is justified in this profile only where the statement is a predicate over committed state — accumulator membership against a root that changes as credentials are revoked, a nullifier derived inside the statement from a secret the verifier never sees, and bitmap indexing that reveals one bit while hiding the rest — jointly, in one proof. Predicates of that shape require additional machinery on top of a signature scheme.

### 1.3 The interaction being addressed

The A2A security schemes fit the phase where both parties have decided to do business and are willing to be known to each other. That is most A2A traffic and this profile changes none of it.

The phase addressed here is earlier. A procurement agent discovers forty supplier agents advertising a `quote.request` skill and queries each for price and capacity. Each supplier requires callers to be authorized before it will quote, because a quote discloses pricing it treats as confidential. Under a bearer credential, being authorized and being identified are the same act: all forty suppliers learn which manufacturer is sourcing which part, on what timeline, including the thirty-nine that win nothing. Any two colluding suppliers confirm they were approached by the same buyer. The credential also discloses the buyer's entire authorized category list, not the one category this request concerns.

Anonymous while shopping, named when transacting. When the buyer selects a supplier and places an order, it authenticates normally under whatever that skill's `security_requirements` name.

The same shape recurs where an agent surveys regulated data providers before subscribing, compares model or compute vendors where the fact of evaluation is itself a signal, or queries several databases where the query pattern reveals a hypothesis. In each case authorization is required at discovery time and attribution is not.

### 1.4 What a presentation does not establish

A presentation proves a property of a *credential*. It establishes computational integrity for the statement proved and says nothing about what the agent will do with the response, what model it runs, what its instructions say, or whether its subsequent conduct is honest. An agent can correctly prove it is authorized and then behave badly, and the proof still verifies. A valid presentation is not evidence that the agent is competent, honest, or aligned, that its outputs are correct, that it will honor a quote, or that it will handle data as promised.

Anonymity also removes post-hoc attribution. A verifier that accepts anonymous callers gives up its ability to identify an abuser after the fact. That is the reason the specification restricts the profile to discovery and quoting, and it is the reason for the one requirement in the specification that is verified by inspection rather than by a wire test: a zk-A2A presentation is not a sole authorization basis for an operation that moves funds, creates a payment obligation, executes an order, or otherwise binds a party to a financial outcome. That boundary is what makes the rest of the privacy argument defensible. Where a legal regime requires that the identity of an acting party be recorded — KYC/AML, healthcare access logging, financial recordkeeping, export control — the requirement is attribution, and a mechanism whose purpose is to prevent attribution does not satisfy it and cannot be configured into satisfying it. The profile defines no identity escrow, no conditional deanonymization, and no trusted opener.

### 1.5 Glossary of the terms this profile owns

The specification defines four terms specific to the profile; the rest of the vocabulary is standard and is used as the cited literature uses it.

- **Statement** — the assertion proved, expressed as a fixed set of constraints, identified by a URI fragment. A verifier knows what was proved because it holds the corresponding verification key.
- **Scope bitmap** and **skill index** — a bit vector inside the credential, one bit per index, committed in the leaf. The statement proves `scopeBitmap[skillIndex] == 1` without revealing any other bit. The index-to-capability mapping is published by the issuer and is authoritative there, never at the verifier.
- **Nullifier** — a deterministic value derived inside the circuit from the credential secret and a scope value, published as a public output.
- **Anchor** — a short commitment the verifier trusts: here a fixed-depth Merkle root committing to the currently valid credential leaves, usable only as the `root` member of a signed root statement.

---

## 2. Design constraints imposed by A2A

Most of the profile's shape is forced. This section names the forcing constraints and what each one removed from the design space.

### 2.1 Message ordering forecloses binding at first contact

At first contact, every value available to bind a presentation to is prover-chosen. `Task.id` is generated by the server in response to the opening message, so it does not exist when the client composes that message. `message_id` is created by the message creator. `context_id` is client-supplied when present. A freshness value chosen by the prover does not establish freshness to the verifier, because the prover is exactly the party a replay defense constrains.

Transport layers do offer server-contributed values. TLS exporters (RFC 5705, RFC 8446 §7.5) bind the channel and would be the obvious source. They are not exposed by most HTTP client stacks, they change meaning wherever TLS terminates at a proxy or load balancer, and they are not available identically across A2A's bindings. Server certificate keys have the same problems plus rotation.

Two further properties push in the same direction.

**Activation is confirmed in the response.** The client's request header states an intent; the server's echo states what it activated. A prover that presents before seeing the echo presents into an exchange whose handling is unknown, and a presentation is not retractable. The nullifier it carries is consumed for its scope whether or not the peer looked at it.

**A nonce alone does not bind the verifier's identity.** A verifier-chosen random nonce leaves a relay open: a malicious verifier V1 obtains a challenge from an honest verifier V2, forwards it to the prover, and relays the prover's presentation back to V2. Binding therefore has to include an identifier of the verifier the prover believes it is addressing — the role `aud` plays in an SD-JWT Key Binding JWT and `client_id` plays in an OpenID4VP request.

The consequence is the `TASK_STATE_AUTH_REQUIRED` round trip, which is the same flow shape `experimental-ext-oid4vp-auth` uses. The difference is what the client returns, not how the turn is structured.

The costs are real and a deployment should price them:

- **One extra round trip on every first contact.** In a discovery flow querying many providers this roughly doubles the request count before any quote returns.
- **The skill is disclosed before authorization.** The opening message names it in the clear, so a verifier learns what an unauthenticated party wanted even if that party never proves anything. This is inherent to scoping the challenge to a skill.
- **The anchor selection is disclosed**, narrowing the candidate set to that root's population.
- **The nullifier is a pseudonym within its scope.**
- **Challenge state is per-session server state.** An unauthenticated party can force challenge minting, which is a memory cost and a denial-of-service surface. Rate-limiting challenge issuance per source means retaining transport identifiers for a window, which is in tension with the minimization the same section asks for.
- **A canonical `verifier_id` has to be configured.** A verifier reachable under several names that does not settle on one produces prover-side aborts that look like outages.
- **Proving cost is paid by the client, per verifier.** At the reference ~200 ms, a client shopping 50 providers spends about 10 seconds of proving, parallelizable across providers.

Binding does not by itself deliver the relay defense. The prover has to compare the challenge's `verifierId` against the card it fetched and against the transport-authenticated peer. Without that comparison, a verifier that relays its own live challenge to a victim prover and forwards the resulting proof onward succeeds, because the proof is bound to *a* verifier but the prover never established whose. The binding is to a *name*, and the strength of the binding is the strength of the transport authentication behind that name. On a custom binding without comparable peer authentication, the prover's check degrades to a consistency check between two values the same party supplied.

### 2.2 There is no canonical transcript across the transports

A2A defines its object model in protobuf and carries it over HTTP+JSON, JSON-RPC, gRPC, and custom bindings. The serialized bytes of one logical request differ by binding, and protobuf wire encoding is not canonical in any case: field ordering, map ordering, default-value emission, and unknown fields can all vary between conforming encoders. A byte-level transcript taken from one binding does not reproduce under another.

ISO/IEC 18013-5 solves this with `SessionTranscript` over `DeviceEngagement`, `EReaderKey`, and `Handover`, which works because that specification owns a single transport family. A2A does not.

The profile therefore binds over A2A object-model values that are present and identical in every binding, and canonicalizes them itself — the Canonical Message Encoding, `CME(M, op)`, hashed to `requestDigest` and folded into `requestBinding` alongside verifier identity, the challenge nonce, and the skill id. Where a transport binding defines a canonical encoding at its own layer, an implementation can additionally bind that encoding, but conformance is measured against the object-model encoding, since that is the one value both parties can compute regardless of binding.

Three details in `CME` are worth explaining because they look arbitrary:

- **The presence byte.** `O(x) = 0x00` when unset, else `0x01 || B(x)`. Without it an absent field and an empty string encode identically, and an intermediary can convert one into the other without breaking the binding.
- **The presentation part is excluded from the digest.** Unavoidable — the proof cannot commit to itself. The exclusion creates a hazard: an intermediary could append a part matching the exclusion rule and carry unbound content through. That is why a message carries at most one part that parses as a presentation and why a verifier rejects rather than selecting one when it finds two.
- **The abstract operation identifier is bound, not the method name.** The JSON-RPC envelope, the gRPC method path, and the HTTP request line are outside `CME`. Without `op`, the same `Message` could be moved between a non-streaming and a streaming operation. Method names differ per binding, so binding a literal method name would break cross-transport identity. `a2a.message.send` and `a2a.message.stream` stay fixed even if a future core version renames the underlying operations.

What the binding does not cover, stated plainly because each is a cost:

- **The TLS channel.** Audience binding means a presentation relayed to a verifier with a different `verifier_id` fails, and relaying it to one with the same `verifier_id` gains the relayer nothing. The binding does not detect a passive network position, and it does not detect an active attacker who captures and races a verbatim copy: the copy is indistinguishable from the original, the copy is accepted, and the legitimate message is then rejected as an unknown challenge. Confidentiality and integrity of the transport remain necessary.
- **HTTP headers, including `A2A-Extensions`.** A transport-level artifact, checked separately. The cost is that a disagreement between the header and `Message.extensions` is invisible to the binding.
- **The response.** A verifier has no artifact here with which to prove to a third party what it answered.
- **Time.** Freshness comes from challenge expiry, not from a timestamp inside the binding.
- **The candidate set.** A nullifier presented inside a small enumerable candidate set is close to an identifier, and nothing in the binding substitutes for §4.

One implementation detail deserves its own line because the failure is silent. `requestBinding` is a declared public input, and the circuit contains at least one constraint involving it. A public input that appears in no constraint is removed by the compiler, after which it is unconstrained and binds nothing while still appearing in the public signal vector. In Circom the minimal idiom is a self-multiplication into a discarded intermediate. Checking that the signal survives compilation means inspecting the emitted R1CS, not assuming.

### 2.3 No new task states and no new enum values

A2A extensions do not add `TaskState` values, extend enums, define RPC methods, or define message types. Everything the profile says therefore has to ride existing states plus `metadata`.

Two consequences follow.

**A failure vocabulary is needed, and it is only advisory.** Without a shared vocabulary, two independent implementations emit different strings and generic tooling cannot distinguish a proof failure from an execution failure. So the profile defines a registry of lowercase tokens (`zk-a2a/<slug>`) carried in `TaskStatus.message.metadata` keyed by the extension URI, with outcomes mapped onto `AUTH_REQUIRED` for a demand or a retryable rejection, `REJECTED` for a terminal policy refusal, `FAILED` for a verifier-side fault, and `WORKING`/`COMPLETED` on acceptance. A generic, extension-unaware A2A client sees only the task state and ignores metadata it does not understand. The protocol does not depend on any peer parsing any token — the tokens exist so heterogeneous tooling can tell proof failures from execution failures when it does understand them.

**Error carriage has an ordering trap.** Verified against `a2a-sdk` 1.1.2: `a2a/utils/error_handlers.py::build_error_details` always emits the core `a2a-protocol.org` `ErrorInfo` as the leading detail; the REST client helper scans `details`, stops at whichever `ErrorInfo` comes first whether or not the reason maps, does not inspect `domain`, and maps `reason` to an A2A exception; the JSON-RPC client selects the exception from the numeric code and takes `data` from that same leading `ErrorInfo`, also without inspecting `domain`; the gRPC client iterates all details and filters on `domain == 'a2a-protocol.org'`, so it is order-independent. A zk-A2A detail placed ahead of the core one would suppress the core reason mapping on REST and hand the client zk-A2A metadata as the core error data. Hence: append, never lead. The cost of appending is that the SDK's default error mapping does not surface the zk-A2A detail at all, so an extension-aware client parses the raw details list itself. That is why the in-task metadata channel is the normative one and the `ErrorInfo` channel is secondary.

One privacy rule in this area is load-bearing enough that it stayed normative: no nullifier, scope value, counter, or other credential-derived value appears in a failure response or in `ErrorInfo.metadata`. The SDK serializes error data unaltered into `ErrorInfo.metadata` and returns it to the client, and carries an explicit security warning to that effect.

### 2.4 A fourth constraint: unauthenticated card discovery

A2A discovery works by fetching Agent Cards from a well-known URL. For a first-contact client with no prior relationship, that fetch has to succeed without credentials or discovery fails. That constraint is the subject of §4 and it is the most consequential one in this document.

It also forces a placement decision. `AgentCapabilities.extended_agent_card` allows a fuller card behind authentication, and operational detail can be moved there. Everything needed for first contact cannot: obtaining the extended card requires the client to authenticate, and the client is the party whose anonymity this profile protects. Requiring the prover to name itself before proving anonymously is self-defeating.

A second, smaller consequence: Agent Card signatures cover the declaration, because the card-signing procedure canonicalizes with RFC 8785 after excluding `signatures`, so `capabilities.extensions[].params` is inside the signed payload. But that procedure also removes default-valued properties before canonicalization, so a signature does not distinguish a falsey default from an absent key. A security-relevant value encoded as a default and protected by a card signature is not protected.

### 2.5 A constraint the profile imposes on itself: no per-presentation issuer contact

This one is not from A2A. It is the constraint that makes the revocation design what it is.

Any per-presentation query to an issuer — a status fetch keyed to one credential, a witness lookup by index, an introspection call — makes the issuer an oracle that learns which verifier checked which credential and when. All issuer contact in this profile is presentation-independent: whole-artifact fetches on a fixed schedule, identical for every fetcher. Root retrieval is a background task and is never triggered by an incoming presentation or by an unknown key identifier, both because that adds unbounded request-path latency and because refresh timing driven by presentations recreates the same oracle.

The architecture that falls out is the ordinary two-tier PKI split: a slow-moving anchor naming the authority, plus a fast-moving, independently signed, sequence-numbered status artifact carrying state. Same split as a CA certificate and the CRLs issued under it, or a Certificate Transparency log key and its signed tree heads. The issuer key is the slow-moving anchor and should be anchored by something that changes far less often than the roots do — a JWKS document at minimum, preferably an external trust list. Trust lists refresh on the order of hours to months and are unsuited to carrying a value that changes on every issuance and revocation; they are well suited to carrying the key that signs those values.

**The cost is that revocation is never immediate.** Let `T_pub` be the publication interval, `Δ_v` the verifier's configured maximum root age, `ttl` the issuer-declared cache ceiling, `Δ_eff(R) = min(Δ_v, ttl(R))`, and `skew` the tolerated clock disagreement. Let *n* be the number of publication intervals between an issuer accepting a revocation and the first published root that excludes the leaf. Worst-case exposure is

```
E = (n − 1) · T_pub + Δ_eff + skew
```

With the defaults (`T_pub` 900 s, `Δ_v` 3600 s, `ttl` 3600 s, `skew` 60 s) and *n* = 1: `E = 3660` seconds, about **61 minutes**. With *n* = 2: `E = 4560` seconds, about **76 minutes**. Two terms are added when the corresponding features are on. A challenge that carries listed roots forward adds the challenge validity period — which is why challenge expiry belongs in minutes rather than hours. Degraded acceptance replaces `Δ_eff` with `Δ_hard`: with the defaults, up to 24 hours rather than 1 hour. That is the single largest term in the model and it is the reason degraded acceptance is off by default and enabled per anchor.

A deployment that cannot tolerate an hour of exposure lowers `Δ_v`, lowers `T_pub`, disables degraded acceptance, or does not use this profile.

The parameter bounds have reasons. Setting `Δ_v` below `2·T_pub + skew` guarantees intervals during which no honest prover can satisfy the verifier. A `ttl` shorter than the publication interval guarantees that honest verifiers periodically hold nothing valid. `Δ_hard` is capped at one week because beyond that horizon the accumulator adds no revocation value over ordinary credential expiry, and a deployment operating there should say so rather than describe itself as having revocation.

**Heartbeat republication.** Issuers republish at every interval boundary whether or not the leaf set changed. If republication happened only on change, republication timing would itself disclose revocation events, and a verifier could not distinguish "nothing has been revoked" from "the issuer has stopped publishing." A heartbeat increments the epoch, updates `iat`, and leaves the root equal to the previous root. Off-schedule publication for an urgent revocation is permitted, with two consequences: it discloses that an urgent revocation occurred, and it does not shrink the exposure window, because previously published roots stay acceptable until they age out. The levers that shrink exposure are a shorter `ttl` and a smaller `Δ_v`, not faster publication.

**Degraded acceptance.** Two obvious policies both have costs. Failing closed on every stale root turns an issuer's publication hiccup into a total outage of the discovery phase, and hands an adversary with network position a denial of service that doubles as a deanonymization lever. Warning and passing — what ETSI TS 119 615 prescribes for a trusted list whose next-update date has passed — is defensible when the stale artifact names certificate authorities, and weaker when the stale artifact *is* the revocation state of the credential being presented. The middle position the profile takes is: off by default, per-anchor opt-in, never a silent fallback, no side-effecting operation authorized, disclosed to the caller. The verifier assumes the caller may already be revoked and releases only information whose disclosure to a revoked counterparty is tolerable. Quotes frequently are not — pricing disclosed to a revoked party is disclosed permanently — and a verifier for which that is unacceptable should not enable degraded acceptance at all.

**A history window is mandatory or honest provers fail at random.** A prover that fetched deltas and built a witness against epoch *e* loses whenever the issuer publishes *e+1* mid-flight. This is the same knob other nullifier systems expose. Semaphore's per-group `merkleTreeDuration` defaults to one hour. World ID's identity manager exposes a settable root-history expiry, and its proof-verification API documents a configurable maximum root age defaulting to 7,200 seconds with a documented range of 3,600 to 604,800 seconds — the same order of magnitude as the defaults here, arrived at independently. Both of those were tuned for a deployment with a single on-chain writer imposing canonical ordering. A zk-A2A deployment may or may not have such a writer, so the window here is defined against a signed `iat` and a declared `ttl` rather than against block height. That works in either case, at the cost of depending on loosely synchronized clocks.

**Which root a prover picks is a fingerprint.** Two rules pull opposite ways. Prover-uniformity: prove against the oldest root still inside the accepted window, so provers with different refresh cadences are indistinguishable; the cost belongs to the verifier, since a credential revoked after that root was published still verifies, and the window is exactly the verifier's stated revocation-latency tolerance. Freshness: always prove against the newest root, which minimizes the verifier's exposure but reveals that this prover refreshes promptly, and a prover whose witness updates lag consistently is identifiable by its lag across sessions. The profile recommends prover-uniformity, because a fingerprint that persists across sessions erodes the property the profile exists to provide while the extra exposure is bounded by a window the verifier itself chose. Verifiers that cannot tolerate it narrow the window rather than relying on prover choice.

**Witness maintenance relocates issuer contact, it does not eliminate it.** A holder's witness is its Merkle path. Every change to any leaf changes the root and changes exactly one sibling on every other holder's path. The delta feed — per epoch, the list of `(index, newLeafValue)` pairs changed since the previous epoch, addressable by epoch number — means every holder downloads the same artifact and the issuer learns that some holder fetched, not which leaf that holder owns. Feed size is proportional to churn, not to population. A per-holder witness service ("give me the path for index *i*") is the alternative and is not recommended: it reveals *i* to the issuer, and if holders fetch immediately before presenting, fetch timing correlates with presentation timing. Holders that fetch on the issuer's schedule regardless of whether they intend to present pay bandwidth and wake-ups in exchange for fetch timing that carries no information about presentation activity.

AnonCreds is the precedent worth studying for the cost line. Its equivalent witness material, the tails file, is reported at up to roughly 1 GB per revocation registry sized for on the order of 100,000 credentials, growing linearly with registry size, and the AnonCreds specification's own revocation discussion treats holder-side retrieval as a scalability limit. Delta encoding keeps the steady-state cost proportional to revocation rate rather than to population, but a holder that has been offline for a long time replays every intervening delta or refetches the full sparse leaf set — which is why issuers retain deltas for at least `Δ_hard`.

The delta feed discloses issuance and revocation *rates* and the exact timing of both. It does not disclose which holder was affected, and a revoked leaf is not linkable to any past presentation, because presentations disclose no index and the nullifier is scope-bound. Rate disclosure is accepted rather than mitigated; padding the feed to a constant size is available at a proportional bandwidth cost.

**Revocation is replacement, never re-indexing.** Removal replaces the leaf value with the empty-leaf value at its existing index. Re-indexing changes the position of every subsequent leaf and invalidates every holder's path at once, turning one revocation into a global witness outage. A vacated index can be reused for a later issuance: because the leaf value is a commitment under a fresh secret, reuse discloses nothing beyond the fact that a slot changed, which the delta feed discloses anyway.

Because membership in the current root is what the circuit proves, non-revocation is not a separate predicate and the credential carries no revocation-status attribute. The cost of that simplicity is that status is binary. A deployment needing "suspended" as distinct from "revoked" runs a status list alongside the accumulator or commits the status into the leaf and proves a predicate over it — which changes the circuit, hence the parameter set identifier and the ceremony. Scope change is also revoke-and-reissue, since the bitmap is inside the leaf preimage, so widening or narrowing a credential's scope is two tree writes. Fine-grained scopes mean more reissuance churn, and churn is visible in the delta feed.

**Equivocation.** The default publication venue is the issuer's own HTTPS endpoint, whose weakness is that a compromised or dishonest issuer can serve one root to one verifier and a different root at the same epoch to another. Two signed statements at one epoch are self-authenticating evidence of issuer misbehavior, so a verifier that sees both rejects both and uses neither. That detects equivocation only when a single verifier happens to see both statements, which a targeted adversary can avoid. Submitting root statements to a CT-style append-only log makes equivocation detectable by any monitor; the cost is additional infrastructure, a second set of operators, and a monitoring function that somebody actually runs. Anchoring roots on a public ledger gives a single canonical writer ordering, imposes settlement latency on republication, and is frequently refused by enterprise buyers in regulated settings. The profile requires neither and treats neither as the default.

---

## 3. Nullifier scope

### 3.1 What the nullifier restores, and what it costs to restore it

A presentation that hides the holder also hides repetition. Two proofs against the same anchor and the same skill index are, to the verifier, two proofs against the same anchor and the same skill index; it cannot tell whether one holder presented twice or two holders presented once each. That is the property the profile is selling, and it is also a loss. Nearly everything a verifier ordinarily does with a caller — count it, rate limit it, attach a quote or a hold to it, notice that the counterparty changed mid-conversation — rests on answering "same party or not."

The substitutes available without help from the statement are worse than they look. Transport continuity answers "same connection," not "same holder," and a caller that reconnects or is load-balanced looks new. Requiring an identifier in `metadata` reinstates exactly what the proof removed, in a field the client chooses.

Against that baseline the nullifier restores exactly one predicate: equality of holder within a chosen domain. `nullifier = H(secret, sessionScope)`, computed inside the circuit and published as a public output; in the reference instantiation `H` is circomlib's two-input Poseidon over BN254 `Fr`. Assuming collision resistance, two presentations produce the same nullifier when the same secret is used under the same scope, and different nullifiers otherwise. Choosing the scope is choosing the exact domain within which the holder is linkable.

Two consequences that are easy to miss. Two credentials sharing a secret — a re-issuance that reuses the holder's secret, for example — are indistinguishable by nullifier, so an issuer that wants distinct credentials to be countable separately issues distinct secrets. And a nullifier is only as private as the secret is unpredictable: anyone who later learns a credential secret can recompute every nullifier that credential ever produced, given the scope inputs, and the scope inputs specified here are all public.

### 3.2 Scope and freshness have to be separate values

One value serving as both the nullifier scope and the anti-replay challenge forces a choice between two incompatible behaviors. If the value changes on every request, every nullifier is unique, the nullifier store never observes a repeat, and counting and rate limiting have nothing to work with — every scope choice below becomes indistinguishable from every other. If the value is coarse enough to be useful for counting, it is by construction reused across requests, so its presence in a proof says nothing about whether that individual request is fresh.

Hence two public inputs: `sessionScope`, coarse, defining the nullifier's uniqueness domain; and `requestBinding`, per-presentation, carrying freshness and binding the proof to the specific request it authorizes. Replay defense rests on the single-use challenge and `requestBinding`, never on nullifier uniqueness; rate limiting keys on the nullifier, never on `requestBinding`.

The cost of the separation is one additional public input, one additional verifier-side recomputation per presentation, and a circuit change. The reference implementation as measured conflates the two: it has one binding input (`sessionNonce`) and its verifier treats a repeated nullifier as a replay. That is the largest gap between the specification and the code.

### 3.3 The three candidate scopes

Three scope constructions are available from A2A lifecycle objects.

**`context_id` scoping.** The nullifier is constant for the lifetime of one conversation.

- *Links:* every presentation within one `context_id` to one holder — every turn, every task in that context, regardless of elapsed time, network path, or transport connection.
- *Marginal leak over the protocol baseline:* small. `context_id` already travels in the clear on every `Message` and every `Task`, so the verifier can already group those turns. The nullifier adds that the grouping survives a client rotating everything else it controls while keeping the context alive. A client that wants to avoid the grouping abandons the context.
- *Cross-context linkage:* none from the nullifier.
- *Rate limiting:* per-conversation only. A fresh nullifier is one new context away, so this construction provides no cross-session Sybil resistance.
- *Round trips:* the `AUTH_REQUIRED` round trip is paid once per conversation, because the context persists across sibling tasks.
- *Integrity hazard:* A2A permits a client to supply a `context_id`, so a client has influence over its own scope input. Handled by verifier-side recomputation and by putting `verifier_id` inside the scope.

**`task_id` scoping.** The nullifier is constant for the lifetime of one task.

- *Apparent privacy gain:* two sibling tasks in the same context carry different nullifiers. The gain is largely illusory at the A2A layer, because both tasks carry the same `context_id` in the clear and the verifier links them from that alone. Task scoping buys unlinkability against an observer that sees nullifiers but not `context_id`, which is not the verifier's position.
- *Permits sibling-task reuse:* the uniqueness domain is one task, so a credential can be presented an unbounded number of times within one context by opening sibling tasks, and the duplicate-nullifier observation never fires. Any per-holder counter, quota, or "one anonymous counterparty per conversation" invariant is defeated by opening a new task.
- *Cost:* the round trip is paid once per task rather than once per conversation.

**Time-window (epoch) scoping.** `scope = f(⌊unix_time / W⌋)` — the construction used by Semaphore's external nullifier and by RLN.

- *Links:* every presentation by that credential within window `W`, across contexts and across tasks. Strictly more linkage than context scoping, and it runs against the discovery-and-quoting use case: a caller that queries the same provider on Monday and again on Tuesday is linked if both fall in one window.
- *Buys:* a bound on a holder's activity at one verifier per window — the only one of the three that reaches past a single conversation. It bounds presentations per credential, not per real-world entity.
- *Timing leakage:* the epoch boundary is itself an oracle. Presentations that straddle a boundary become unlinkable, so an adversary who knows `W` and the boundary phase can partition observed activity by time. Where traffic is sparse relative to `W`, a window may contain presentations from a single holder, in which case the nullifier is a stable identifier for that window.
- *Clock skew:* a verifier that tolerates the immediately preceding epoch near a boundary lets a holder straddle and consume two epochs' budget in quick succession; a verifier that tolerates nothing produces spurious failures for clients with modest clock drift.
- *Predictability:* the scope value is derivable from the clock, so a party that captures a presentation can attempt to reuse it for the remainder of the window. Because the nullifier is identical, an attacker's copy registered first causes the legitimate prover's own presentation to be rejected as already registered. With request binding in force the captured presentation is still bound to one request and one challenge, but the denial-of-service and hijack surface is real, and a predictable scope value is a poor fit where an active network attacker is in scope.
- *Collusion hazard:* an epoch scope that does not incorporate verifier identity produces the same nullifier at every verifier the holder contacts in that window, letting two colluding providers link a caller across organizations by nullifier equality alone, with certainty and at zero cost. This is the decisive argument against a globally scoped epoch nullifier, and the profile forbids it.

| Scope | Links within | Links across contexts at one verifier | Cross-session rate limiting | Round trips |
|---|---|---|---|---|
| `context` | one conversation | no | no | one per conversation |
| `task` | one task | no | no | one per task |
| `epoch` W | window W | **yes** | yes, per credential per verifier | one per conversation |

### 3.4 Why verifier-bound context scope is the default

Context scoping has the smallest marginal leak over what A2A already discloses, pays the round trip once per conversation rather than once per task, and preserves the one predicate a verifier genuinely needs during a quoting exchange — continuity of counterparty within the conversation, so a quote or a hold can be attached to a party that cannot be named. Task scoping's apparent privacy gain does not hold against the verifier, which is the adversary the scope is chosen against, and it removes any per-conversation invariant. Epoch scoping is the only one that reaches past a conversation, and the reach is precisely the linkage the discovery use case is trying to avoid.

`verifier_id` is inside the scope for a specific reason. `context_id` travels between agents and a client may propose one. Without `verifier_id`, two providers that both see the same `context_id` value — because a client reused it, because an orchestrator propagated it down a call chain, or because two colluding providers agreed on a common value — would observe equal nullifiers for the same holder. Including `verifier_id` removes that linkage regardless of who chooses `context_id`. Including a `scopeName` domain separator means a value that happens to serve as both a task id and a context id cannot collide across the two profiles.

The costs are real but small. A verifier that changes its `verifier_id` — by moving its Agent Card, or by rotating its card-signing key under the thumbprint option — changes every scope it participates in, resetting counters and breaking nullifier continuity for open contexts. And the construction leaves the candidate-set problem untouched: `verifier_id` is public, so anyone who obtains a credential secret can recompute the holder's nullifiers at any verifier whose card they can fetch.

This mirrors WebAuthn binding `origin` into `clientDataJSON` and SD-JWT Key Binding committing to `aud`: the identity of the party being talked to is part of what gets committed rather than an out-of-band assumption.

One further note on `verifier_id`: any set of endpoints sharing one `verifier_id` is one linkage domain, since they see identical nullifiers for the same credential and scope value. `AgentInterface` carries an optional `tenant` routing string precisely because several agents may sit behind one A2A endpoint. Deployments in that shape either include the tenant discriminator in `verifier_id` or accept that co-tenants can link their callers to each other.

### 3.5 A repeated nullifier is the expected steady state

Under context scope a client presenting on turn one, turn two, and turn five of the same conversation produces the same nullifier all three times. A verifier that rejects on repetition rejects its own honest callers. Freshness comes from `requestBinding` and the single-use challenge, and only from those.

A repeated nullifier is significant for exactly two purposes: incrementing the per-nullifier counter used for rate limiting, and establishing that the anonymous counterparty in this turn is the same one as in the previous turn, which is what lets a verifier attach conversational state to a counterparty it cannot name.

A *distinct* nullifier appearing in an established scope means a different secret was used in the same conversation. That is anomalous and a verifier may reject it, at the cost of a false positive against legitimate behavior: a client holding several credentials and switching between them mid-conversation, or one whose credential was re-issued with a fresh secret during the context, is indistinguishable from a relayed or shared presentation at this layer.

### 3.6 Cloneable holders, and the fleet trap

Classical non-transferability arguments assume a scarce, non-cloneable holder. Camenisch–Lysyanskaya's all-or-nothing construction assumes the master secret also protects things the holder will not surrender; DAA and EPID assume a key sealed in hardware. Neither assumption holds for a containerized agent. Agents are cloned by design — autoscaling, image distribution, forks — and an operator duplicating its own agent is not an adversary under those models.

Holder binding and any candidate set are therefore at **operator granularity**, not instance granularity, unless the secret is per-instance and rooted in per-instance TEE or KMS material. A valid presentation is not evidence about which instance is calling.

The live interoperability trap: a fleet of *N* replicas sharing one credential secret computes **identical** nullifiers under the same scope. Under a policy permitting only one acceptance per scope, an honest fleet triggers the verifier's per-scope limit. A deployment either coordinates so that exactly one replica presents per challenge, or issues per-instance secrets. Per-instance secrets have their own cost: issuance and revocation volume scale with fleet size, the issuer learns the fleet's size and its scaling pattern from issuance traffic, and each instance's leaf sees less traffic, which sharpens any per-leaf behavioral fingerprint.

### 3.7 The rate-limit nullifier and its prior art

A deployment needing a bound on a holder's activity beyond one conversation can require a second nullifier under an epoch scope, presented alongside the session nullifier, from one proof and one secret. Two separate proofs would let a client use one credential for the session nullifier and a different one for the rate-limit nullifier, defeating the count.

Requiring it is a material privacy disclosure, and the disclosure is the pairing itself: presenting both nullifiers in one proof tells the verifier that this context belongs to the holder identified by the epoch nullifier, so every context that holder opens within the epoch becomes linkable. That is why it defaults to off and is declared in the Agent Card, so a client can decline before presenting anything.

Nothing in the rate-limiting design is new; it selects among known constructions.

**RLN**, derived from Semaphore, uses an epoch-scoped external nullifier together with Shamir secret sharing: each message carries one share of the holder's identity secret, so exceeding the per-epoch limit yields enough shares to reconstruct that secret, which permits slashing and removal of the holder's leaf. This is the established way to make an epoch limit self-enforcing rather than merely observable. The cost is severe and belongs on the table before adoption, not after: exceeding the limit reveals the credential secret to the verifier, which then permits that verifier to recompute and match every nullifier that holder ever produced in any scope the verifier can construct — retroactively deanonymizing the holder's history with that verifier, not merely the offending epoch. Appropriate where the limit is a genuine abuse threshold, wrong where it is a routine quota.

**Privacy Pass rate-limited issuance** takes the opposite architectural approach: a separate Attester, distinct from Issuer and Origin, enforces per-origin per-client limits at *issuance* time, so the Origin learns nothing about client identity and the presentation carries no counter at all. The base documents are RFC 9576/9577/9578. The rate-limited variant is `draft-ietf-privacypass-rate-limit-tokens`, whose latest revision (-06, April 2024, intended status Experimental) expired in December 2024; a deployment adopting that architecture is relying on an expired Internet-Draft and should confirm its current state. Where a deployment can accommodate a third party, this is the better architecture: it moves the counter off the presentation path entirely and leaves the verifier with no per-holder state to retain. The cost is a party that has to be operated, trusted not to collude with the origin, and available at issuance time.

What nullifiers do not give, under any of these constructions, is Sybil resistance. Under the default scope a holder obtains a fresh nullifier by opening a new context; under the epoch profile it obtains one at the next epoch boundary, and one per credential it holds. Nullifiers bound *rate*, not *identity count*. A deployment needing identity count obtains it at issuance — one credential per real-world entity, enforced by the issuer — or requires an identified scheme.

### 3.8 Retention is a privacy liability, not a storage cost

A retained nullifier is a value that anyone who *later* learns a credential secret can recompute and match against, since `verifier_id`, the scope value, and the epoch parameters are all public. A nullifier log is therefore a retroactive-deanonymization oracle conditioned on a future compromise, and it is discoverable, subpoenable, and breachable. Equality is the entire signal a nullifier carries, so anywhere two of them can be compared is a place where linkage happens — which is why nullifiers stay out of artifacts, message parts, error objects, and general application logs, and why they expire with their scope. The accepted cost is that the store cannot be used for cross-scope abuse analytics.

Two operational notes. Duplicate detection and counting are atomic per key, and the store is consistent across all verifier replicas that can terminate the same session. A verifier distributed across replicas without a linearizable store enforces its limits per replica rather than globally, multiplying the effective limit by the replica count, and detects repetition only when a retry happens to land on the same process. This is a common and silent failure; the reference implementation's in-process store is unsuitable for deployment and is documented as such. And loss of the nullifier store resets every counter derived from it, after which the holders whose budgets were consumed become indistinguishable from new ones. Where challenge records live in the same store, the loss is self-limiting in one respect — every presentation binds to a challenge the verifier issued, so after such a loss the verifier rejects presentations bound to challenges it can no longer find. Where challenge records are held separately and survive, that mitigation does not apply, which is an argument for colocating the two.

---

## 4. Anonymity sets and the enumerable population

This is the most important section in this document, and it is a negative result. It is stated in full rather than summarized because a deployment that does not measure its candidate set will ship anonymity that is decorative and will not know it.

### 4.1 Definitions

For a credential presentation, define the **scope tuple**

```
Σ = (anchorRoot, skillIndex, epoch)
```

`anchorRoot` and `skillIndex` are public signals whose values the prover's credential and request determine. `sessionScope`, `requestBinding`, and `nullifier` are verifier-chosen or uniform-appearing and do not partition the population. `epoch` is the interval during which the presented root is inside the verifier's accepted staleness window; the verifier observes presentation time regardless, so time is part of the partition whether or not the profile names it.

Define the **candidate set** `C(Σ)` as the set of agents that could have produced a presentation with that scope tuple: agents holding an unrevoked leaf under `anchorRoot` whose scope bitmap has bit `skillIndex` set, during that epoch. Define `k = |C(Σ)|`.

The zero-knowledge property guarantees that a verifier learns nothing beyond membership in `C(Σ)`. It does not guarantee that `C(Σ)` is large. At `k = 1` the proof names the prover exactly, while producing a document that looks like a privacy mechanism.

### 4.2 Threat model

The adversary is a passive crawler that may also act as an ordinary A2A client and as one of the verifiers.

- **T1 — Unauthenticated card retrieval.** It can fetch the public Agent Card of any agent that serves one without authentication. In `a2a-sdk` 1.1.2 the path is `/.well-known/agent-card.json` (`a2a.utils.constants.AGENT_CARD_WELL_KNOWN_PATH`), served without authentication by the SDK's default card route.

  Note precisely what is and is not assumed. The core A2A specification does not state that the public card has to be served unauthenticated; it permits an agent to protect its endpoints, and it defines `AgentCapabilities.extended_agent_card` as the authenticated tier, requiring the client to authenticate using a scheme declared in the public card. T1 is conditioned on the **open-discovery deployment mode** — a first-contact client with no prior relationship can only retrieve a card served without credentials — and that mode is exactly the one this profile targets. A deployment that gates its public card raises the crawler's per-candidate cost and gives up open discovery in the same move; that trade is real and operators should make it deliberately. It does not remove enumeration: registries, catalogs, referrals, and T3 remain.
- **T2 — Card content in the clear.** From a retrieved card it reads `skills[]`, `security_schemes`, `security_requirements`, `provider`, `version`, and `capabilities.extensions[]` including each `AgentExtension.uri` and its `params`.
- **T3 — Activation echo.** It can send a request with the extension URI in `A2A-Extensions` to any agent and read the response header to learn whether that agent activated the extension. This confirms support for agents whose cards are incomplete or stale.
- **T4 — Verifier position.** It operates one or more verifiers, observing presentation timing, source addresses, TLS and HTTP client fingerprints, requested skills, and quote contents, and may collude with other verifiers.
- **T5 — Issuer-side observation.** It observes the published root sequence and, where the leaf count is published, the issuance population and its change over time.

The adversary is **not** assumed to break the proof system, compromise an issuer's signing material, compromise the trusted setup, or observe traffic between two other parties.

T1–T3 require no privilege and no credential. The cost is one HTTP request per candidate.

### 4.3 The enumeration procedure

1. Assemble candidate origins from agent registries and catalogs, DNS enumeration, certificate transparency logs, and the link graph formed by `provider` and `documentation_url` fields on cards already retrieved.
2. `GET {origin}/.well-known/agent-card.json` for each. No credential is presented.
3. Retain cards whose `capabilities.extensions[]` contains an entry with `uri == "https://w3id.org/zk-a2a/v1"`.
4. Partition the retained set by the anchors named in that entry's `params`.
5. Within each partition, retain agents whose `holderDeclaration` covers the skill index in question.
6. Optionally confirm each candidate with T3.

The result is a list of named organizations, recomputable at any time at the cost of one HTTP GET per candidate. It is not a bound derived from a modelling assumption.

### 4.4 What the list is and is not

The procedure enumerates agents that *publish a card declaring this extension*. That population overlaps `C(Σ)` but is not equal to it, in both directions.

**Over-count.** A card entry declaring accepted trust anchors is a statement of *verifier* policy. It is not evidence that the publishing agent holds a credential. Counting verifier-side declarations as candidates inflates `k` and is the most likely way for a deployment to overstate its own privacy. This is why the declaration schema separates `holderDeclaration` from `trustAnchors`, and why step 5 counts only the former.

**Under-count.** A caller that publishes no card, or whose card carries no holder declaration, is not enumerable through T1 and does not appear. The argument is strongest in the cross-organizational case this profile targets, where callers are themselves discoverable agents; it is weakest for deployments whose provers are not discoverable.

The structural result is about *partition structure*: A2A's discovery model publishes, at retrievable URLs, the machine-readable attributes that define the partitions — which anchors exist, which skills exist, and which named organizations participate. Where callers are themselves published agents, the candidate set of provers is enumerable directly.

### 4.5 Comparison with the deployment settings the prior art assumes

| Setting | Population sharing the credential | Enumerable by a verifier? | Who can set a floor |
|---|---|---|---|
| Privacy Pass | Clients under one issuance configuration | Not from published data — clients are browsers, not published endpoints | Deployment; RFC 9576 warns that each additional partitioning dimension multiplies tracking granularity and advises bounding concurrently active issuance configurations |
| WebAuthn / FIDO basic attestation | Devices sharing an attestation batch key | Not from published data | Certification guidance: a batch shared by at least 100,000 devices |
| EPID | Members of a group | Not from published data | The silicon vendor sizes the group |
| W3C Bitstring Status List | Credentials sharing one published list | The list is public; the holders are not | The specification sets a minimum list length of 131,072 entries as a herd-privacy floor |
| EUDI wallet instances | Wallet instances under a scheme | Not from published data | The scheme owner |
| **zk-A2A over A2A** | **Agents holding a credential covering skill index *i* under root *R* in epoch *e*** | **The card-publishing subset is, offline, by any crawler (§4.3)** | **Issuers, through issuance policy; registries and taxonomy owners, through skill granularity — each only over the population it controls** |

Two differences compound, and they are different differences.

**(i) The partition is computable, not assumed.** In every other row the analyst reasons about a population the verifier cannot list. Here the verifier can list the published part of it, exactly, for free.

**(ii) Control over the population is distributed.** In every other row a single party controls the population and can mandate a floor: FIDO certifies manufacturers, the silicon vendor sizes the group, the status-list issuer allocates slots. In an open A2A deployment the population is the union of independent organizations' issuance and publishing decisions. A floor is still reachable — an issuer can decline to issue a credential whose scope tuple would be near-unique, and a registry or taxonomy owner can coarsen skill indices — but only over the subset each controls, and only as a governance action rather than a wire-format one.

### 4.6 Repairs considered at the extension-field level, and why each fails

**Remove the anchor from the card.** The client has to know which root to prove against before it can prove. If the anchor is not in the card it arrives in the challenge instead. That moves the adversary's cost from one GET to one round trip, which is a rate-limiting change rather than a privacy change: opening a task at first contact is unauthenticated by construction. It has a second cost — a prover that learns the anchors only from the challenge cannot estimate `k` before it has already disclosed capability in the request header. The profile permits either placement.

**Remove the extension declaration from the card.** A client then cannot know the server supports the profile, so it either probes every server (T3 still answers) or the profile is undiscoverable. A2A's extension guidance makes extensions inactive by default so that extension-unaware peers get a baseline experience; that default only works if support is discoverable.

**Move the declaration to the extended Agent Card.** Obtaining it requires the client to authenticate, and the client is the party whose anonymity this profile protects. Requiring the prover to name itself before proving anonymously is self-defeating.

**Encrypt or hash the anchor in `params`.** The value has to be usable by any legitimate first-contact client, so any key required to interpret it is also available to any first-contact client, including the adversary.

**Set `required: true`.** This makes the situation worse: it forces every peer to disclose whether it supports the profile before any other exchange occurs.

**Coarsen `skillIndex` or widen the issuer set.** These do raise `k`, and they are the correct remedy — but they are decisions about issuance policy and taxonomy, taken by issuers and registries, not encodings on the wire.

### 4.7 Why the floor is a SHOULD

An earlier draft made the anonymity floor a MUST with mandatory refusal below it. That was changed deliberately.

Estimating `k` is an open question in this document. Every estimator below has a stated error mode, no zk-A2A deployment exists, and no measured candidate-set size exists for any real population. A requirement implementers cannot evaluate is a requirement they ignore, and a document that ships MUSTs its own reference implementation cannot satisfy teaches a reader that its MUSTs are not testable — which discounts the ones that are. The floor is therefore stated at SHOULD, with concrete guidance on estimating `k` and on what to do when it comes back low.

Two adjacent requirements stayed at MUST, because they survive independently of whether `k` is measurable:

- **No automatic fallback from a zk-A2A presentation to an identifying scheme** in response to a missing activation echo, a root-freshness failure, or any refusal. Anyone who can make a root look stale to a verifier — a network adversary, or a hostile or merely careless verifier — can force the client onto whatever path the client falls back to. If that fallback is an identifying scheme, root staleness becomes a deanonymization oracle: withhold the root, collect the identity. This is a deanonymization oracle regardless of `k`.
- **The implementation reports to its calling application whether an exchange proceeded anonymously or under an identifying scheme.** In the discovery-and-quoting case, the difference between collecting quotes anonymously and collecting them under one's own name is the reason the profile exists, and a library that silently chooses the second has removed it.

Those two are the load-bearing part of what the floor was protecting.

The floor numbers themselves: a minimum of 2, since at `k = 1` the proof is an identifier; a recommended default of at least 50; examples in the specification use 500. The 50 figure is chosen for deployability, not derived from a security argument. It is three orders of magnitude below the FIDO and Bitstring Status List floors and corresponds to roughly 5.6 bits of uncertainty, which is weak. Deployments in which anonymity is load-bearing should raise it and should say what value they use. The floor in effect for an exchange is the larger of the two declared floors.

### 4.8 Estimating `k`

Enumerability has one benefit and the profile takes it: what the adversary can compute, the deployment can compute too. The estimator is not free of error.

**Method A — crawl.** Run §4.3 and count, counting only agents that publish a holder declaration. Costs: bandwidth and crawl maintenance; staleness between crawls; no visibility into non-publishing holders; and the crawl traffic is itself observable — a prover that crawls a narrow slice of origins immediately before presenting hands an observer a correlate of what it is about to prove. Crawl results belong in a periodic background process rather than on demand.

**Method B — issuer-attested count.** The issuer publishes, alongside the root, a signed count of unrevoked leaves whose scope bitmap covers each skill index. This is the only method that measures the holder population directly, and it is the method to use where holders publish no holder-side declarations. Cost: it discloses issuance volume per skill to everyone. In most deployments this is already inferable from the accumulator's shape, so the marginal disclosure is small, but the count is public once published.

**Method C — registry-attested count.** A catalog or registry operator publishes counts derived from its own index. Cost: it introduces a party that can lie in either direction, and a prover trusting an inflated count will emit presentations it should have refused. Cross-check periodically against Method A or B.

Guidance that applies to any method:

- **Intersect, do not maximize.** `k_est` is computed over the intersection of every constraint appearing in the public signals — the anchor root, the skill index, and the epoch — because the adversary intersects them. Estimating over the issuer population alone, or taking the maximum over constraints, overstates `k` by orders of magnitude.
- **Verifier-side declarations are not holder evidence.** An agent is not counted as a candidate on the strength of a `trustAnchors` entry.
- **Take the smaller number.** Where a crawl-derived count is smaller than the issuer-published count, use the crawl count.
- **Do not add an allowance for the invisible.** Candidate agents that publish no Agent Card are not enumerable through T1 and are not counted by Method A. The asymmetry is the point: the adversary obtains an exact count of the published population, while the deployment obtains that same count plus a residual it cannot size. A conservative estimator uses the enumerable count as the estimate, not as a lower bound to be inflated.
- **Invalidate on change.** The estimate goes stale when the anchor root changes, when the requested skill index changes, or at the end of the epoch, whichever comes first.
- **Prefer effective size where traffic data exists.** Use the Serjantov–Danezis effective anonymity set size `2^H` with `H = -Σ pᵢ log₂ pᵢ` rather than the raw count. The two differ sharply: a candidate set of 100 in which one agent originates 90% of presentations has `H ≈ 1.13` bits and an effective size of about **2.2**, not 100. Most deployments lack the distributional data, which is why this is guidance rather than a requirement; a deployment that has traffic data and ignores it is overstating its privacy by more than an order of magnitude.
- **Record which estimator produced each decision**, under a bounded retention period. The log is operational data about presentations and, kept indefinitely, becomes a linkage corpus of exactly the kind the nullifier retention rules exist to expire.
- **Keep `k_est` out of outward-facing metadata.** Disclosing it tells the verifier how large the candidate population looks from the prover's vantage point, including whatever the prover knows about non-published holders, which the verifier cannot compute for itself. Disclosing the *floor* is a different matter: it lets a counterparty reason about what a refusal means, and it also tells an adversary the threshold at which this agent stops presenting.

### 4.9 What to do when `k` is low

For a prover:

1. **Do not emit with a warning flag.** Emitting below the floor with a degraded marker gives up the property and keeps the appearance of it. Refusal or deliberate re-classification are the two honest options.
2. **Refuse, and choose how loudly.** Either respond with a `Message` whose metadata carries `zk-a2a/anonymity-floor-unmet`, or abandon the task without responding. The first is more interoperable; it also discloses to the verifier that the peer is a zk-A2A client that measured a small candidate set, which is itself information. This is a deployment choice.
3. **Do not fall back automatically.** An automatic fallback to an identified scheme converts a privacy refusal into a deanonymization. Fallback is an operator decision, per verifier.
4. **Where the anchors are published in the card, drop the header.** Where a prover can compute the estimate before first contact, not listing the extension URI in the request header avoids disclosing capability to a verifier it has already decided not to present to. Where the anchors arrive only in the challenge, the estimate cannot precede the header and that disclosure is unavoidable.
5. **Re-classify the deployment.** If `k` is persistently low, the honest configuration is unlinkability-only mode, which does not claim anonymity and does not enforce a floor. That mode is reached by explicit operator configuration and is not a shipped default; a deployment operating in it does not describe the interaction as anonymous in documentation, marketing, or a privacy notice.

For a verifier:

- A verifier that accepts exactly one anchor, or that scopes a skill so narrowly that few agents can hold it, has set `k` for every caller. Assembling accepted-issuer sets or skill scopes known to reduce `k` below the floors expected callers use is a choice with a stated consequence.
- Publishing the accepted anchor set in the card lets a first-contact prover estimate `k` before disclosing anything. It also supplies the crawler's partition key. Withholding it until the challenge inverts both.
- A verifier may refuse a presentation on the ground that the anonymity it provides is decorative, using the same reason token. This stays available and unchanged.

**What the floor gives and does not give.** It is computed from counts the issuer publishes and the declarer copies; neither is verifiable from the anchor, and a floor met on inflated numbers is met on paper only. It bounds the *size* of a candidate set, not an adversary's posterior over that set — trade lane, cargo type, request timing, language, and volume all narrow the field further, and the presentation being zero-knowledge does not touch any of them. And it says nothing about the network layer. Publishing whatever makes the number auditable — leaf count, issuance policy, or an independently attested membership figure — is worth more than the number itself.

### 4.10 What holds below the floor

Refusing below a floor refuses *anonymity*, not everything the profile provides. What survives at small `k`:

- **No long-lived bearer token crosses the wire.** The credential secret never leaves the holder, and a captured presentation is bound to one verifier, one challenge, and one request, so it cannot be replayed elsewhere. Independent of `k`.
- **No stable revocation index is disclosed.** Revocation status is proved without a per-credential list position, so two verifiers have no shared per-credential identifier to compare. Independent of `k`.
- **The presentation does not itself disclose the rest of the scope bitmap, or the issuer within the proved anchor.** This is a property of the message, not of the interaction: at small `k` a verifier that can name the prover may know its scope and issuer from other sources.
- **Unlinkability across sessions degrades exactly as `k` does, and is vacuous at `k = 1`.** Two presentations by the same agent under different scopes produce unrelated nullifiers and share no prover-specific value — but they do share the anchor root, skill index, parameter set identifier, and proof system. Those are shared with every member of `C(Σ)` and with no one else, so they link the two sessions to precisely the extent that `C(Σ)` is small.

A deployment can honestly describe an interaction as non-bearer and free of a per-credential revocation index at any `k`. Describing it as anonymous requires the population argument.

### 4.11 The issuer can set `k` on purpose

One attack belongs here rather than in a security section, because its effect is on the candidate set rather than on soundness. An issuer can tag a holder by assigning a scope bitmap unique to it, or by placing it under an anchor with few leaves. The proof hides tree position; it does not hide the tree's size or the bitmap's rarity. A holder can defend partially — reject a scope bitmap it can see is distinguishing, monitor the leaf count under its anchor where that is observable — but the defense against one's own issuer is limited.

A sharper version: **selective-revocation probing.** An issuer that revokes exactly one leaf and republishes can observe which sessions subsequently fail, and thereby link a leaf to an observed presentation stream. Mitigations are partial. Verifiers accepting multiple anchors mean a single issuer's probe does not determine acceptance; issuers republishing on a fixed cadence with batched changes mean single-leaf deltas are not isolated. This is the trust assumption every credential system in this lineage carries.

Under issuer hiding there is a further erosion. Issuer hiding provides at most `log₂(|set|)` bits, and verifier-published accepted-issuer lists are typically a handful of entries, so the realistic gain is two or three bits. If only one member of a trust set issues credentials covering the requested skill, the issuer candidate set for that request is one, regardless of set size — which is why the floor is evaluated per `(skill, anchor)` pair rather than per anchor, and why assembling a set whose members' skill-scope populations are disjoint buys nothing. Other channels leak more than the issuer bit anyway: a TLS client certificate, an OAuth `client_id`, the source network, or a resolvable Agent Card URL each disclose more, and presenting a zk-A2A credential over an mTLS-authenticated channel gains nothing from issuer hiding at all.

---

## 5. Other linkage channels

The proof is rarely the weakest channel. Each item below states the mechanism, what it leaks, and the mitigation with its cost.

### 5.1 Skill-scope granularity

A request for a rare skill identifies the caller regardless of the proof. If three agents hold a credential covering `settle-cross-border-fx`, then `k = 3` and no cryptography changes that. RFC 9576 describes the same phenomenon for Privacy Pass: each additional partitioning dimension multiplies tracking granularity.

Skill indices defined at the coarsest granularity the authorization decision tolerates raise `k` by the class fan-out. A bitmap position per skill *class* rather than per skill is the lever. The cost is that the verifier's authorization decision becomes correspondingly coarser, and a caller authorized for the class is authorized for every skill in it.

The collusion form of this is the more insidious one. One presentation reveals one bit, but verifiers that collude across skills accumulate distinct bits per holder until the bitmap itself identifies them. A namespace with many finely divided bits makes each holder's bitmap close to unique. Expressive scope has a direct privacy cost and it is paid by holders, not by the party choosing the vocabulary.

A profile variant proving a disjunction — the bit is set for some index in a verifier-supplied set — raises `k` further, at the cost of additional constraints and of the verifier learning less than its own policy may require. It is a different circuit with a different verification key and would be declared as a distinct parameter set.

### 5.2 Timing

Proving costs approximately 200 ms for the reference credential circuit. `sessionScope` and `requestBinding` are public inputs derived from verifier-chosen values, so the dependent work cannot be precomputed: the proving time sits in the critical path after the challenge arrives.

Timing is not the channel that reveals a caller is a zk-A2A client — the caller already discloses that by listing the URI in the request header. What timing gives is correlation: a roughly constant, distinctive proving delay lets colluding verifiers match one caller's sessions to each other, and lets a single verifier distinguish a proving caller from a caching or replaying one. Under any nullifier scoping coarser than per-context, and epoch scoping in particular, timing becomes the dominant linkage channel rather than a residual one.

Batching or randomized delay defeats timing correlation but adds latency to the phase this profile targets, which is the latency-sensitive one. It is available where a latency budget allows and should not be assumed available.

For a fixed circuit, Groth16 proving time is dominated by circuit size and is already close to witness-independent; the variable parts are witness generation and early-abort paths, which should not vary with witness contents, or timing additionally leaks credential structure. This profile provides no timing-analysis resistance and an implementation should not claim it does.

### 5.3 Agent Card fetch patterns and the network layer

A caller shopping across `N` providers fetches `N` well-known cards. Those fetches carry source addresses, TLS fingerprints, and HTTP client fingerprints. Where providers share a CDN, a WAF vendor, or an analytics vendor, the shopping pattern is linkable at that shared vantage point regardless of what the proofs hide.

This profile provides no network-layer anonymity. A client requiring it obtains it separately — an anonymizing relay, a shared cache, or a registry mirror that fetches on the client's behalf. Each adds latency and a trust assumption. Retrieving cards through a shared cache or mirror trades the mirror's visibility into the shopping pattern for the providers' visibility into it, which is usually the better trade.

Client-chosen identifiers reused across verifier boundaries defeat everything above. This includes connections, session tickets, structured `message_id` patterns, custom metadata keys, and `context_id` in particular: A2A allows an agent to accept a client-provided context identifier and advises that clients should not supply one unless they understand how the server will process it, so a client-chosen `context_id` presented to two verifiers is a shared identifier under this profile even though A2A permits it in general. That is why the opening message carries no `context_id` — the server assigns the context, which is what makes it usable as a verifier-controlled scope value. The cost is that a client cannot attach a session to a conversation of its own choosing at first contact; a client needing continuity reuses a context the same verifier assigned it earlier and accepts the linkage that implies.

`reference_task_ids` pointing at tasks from other sessions links tasks at the protocol layer regardless of what the proof hides.

### 5.4 The `A2A-Extensions` echo

Both directions leak.

The **response echo** confirms to any requester which agents support this profile, including agents whose cards omit the declaration. It is the adversary's cheap confirmation channel (T3) and cannot be removed without removing graceful degradation.

The **request header** discloses to the server, before any proof and before any challenge, that this client is a zk-A2A client. A client that later declines to present has still disclosed capability. The cost of requiring the header on every request — activation is never inferred from an earlier request in the same context or task — is a constant distinguisher on every request from a zk-capable client. That cost was accepted in exchange for a property worth more: a server never verifies a presentation on an exchange it did not activate, and a client never sends one into an exchange whose response has not echoed the URI.

The echo means activated, not verified. A server that echoes and then rejects a presentation is behaving correctly, and a missing echo is evidence of non-activation and of nothing else.

### 5.5 Failure-reason granularity

A verifier that reports precisely which check failed is usually reporting it to the credential's owner, who already knows the credential's contents. The oracle is narrower than it first appears. Two effects are real.

**Verifier-policy mapping.** Reasons naming untrusted or stale anchors, unsupported parameter sets, or index mismatches disclose which anchors this verifier accepts, how stale a root it tolerates, and which index it expects for a given skill. An unauthenticated crawler can harvest that from failed probes and use it as the partition key in the enumeration procedure without needing the card. Where the deployment already publishes those values in its public card, the reason discloses nothing new; where it withholds them until the challenge, it does. Hence the conditional classification: coarse when the corresponding value appears in the verifier's public card, sensitive otherwise, defaulting to sensitive.

**Nullifier-state confirmation.** A reason that positively states that *this* nullifier has already been seen in this scope, returned to a party that did not produce the original presentation, confirms that the holder presented to this verifier in this scope. That is exactly the linkage the nullifier construction exists to keep private. It is the most sensitive reason in the registry.

`zk-a2a/proof-invalid` is sensitive on a weaker ground: it tells an unauthenticated prober that its structural framing was accepted and only the cryptography failed, which is a useful signal when hunting for verifier misconfiguration.

The cost of coarse reporting is not small. An honestly misconfigured client receives an undiagnostic reason and cannot tell a stale root from a wrong skill index from a bad verification key, and will retry uselessly until the attempt bound is exhausted. `zk-a2a/attestation-rejected` is the recommended default outward reason, and a deployment adopting it should provide an out-of-band diagnostic path — a documented support channel, or a test endpoint returning fine-grained reasons to authenticated callers — and should keep the retry bound so an undiagnosable failure terminates instead of looping.

On retries generally: bounded retries give a prober repeated oracle access to the accept/reject decision. The security property comes from single-use challenges rather than from the bound itself, which is why the bound is guidance rather than a requirement; a fresh `challengeId` and `challengeNonce` on every re-challenge is the part that matters and stays normative. Retries within one task do not change the nullifier, because the scope value is unchanged by construction — that is not a linkage regression, since the attempts are already linked by `task_id`, and it is why nullifiers are registered only on acceptance.

### 5.6 Root republication cadence and anchor selection

A rarely-used anchor root is close to an identifier by itself, and it is one of the constraints the estimator intersects. The root a prover chooses within the accepted window is a behavioral fingerprint, addressed in §2.5. And event-driven republication turns the root sequence into a side channel on issuer activity: a root whose leaf count changes by exactly one is visible as such, which is the second reason for the fixed-cadence heartbeat.

There is a tension here that has no clean resolution. A short `maxRootAgeSeconds` narrows the set of holders who could have proved against the current root to those who refreshed within that window. Tight revocation and large candidate sets pull against each other, and a deployment picks a point on that curve rather than optimizing both.

### 5.7 Proof-system and encoding fingerprints

The verification key, parameter set, curve, proof encoding, and serialization all identify the prover's software stack, and a deployment running a bespoke circuit identifies its users by the circuit. A private circuit yields a candidate set of one deployment, so an implementation claiming anonymity uses the profile's published circuit artifacts, identified by the pinned verification key digest.

Byte-level encoding is the finer version of the same problem. Differences in JSON key order, integer formatting, or point compression are stable fingerprints and are trivially collected by any verifier. The specification asks for a canonical, byte-indistinguishable encoding — but at SHOULD rather than MUST, because the flag-bit and byte-order convention for the compressed proof differs between the libraries in common use and has not been pinned, and because the reference implementation currently ships the toolchain's JSON proof object rather than a compressed byte string. Requiring what the author's own implementation cannot satisfy discounts every other requirement in the document. This should be promoted to a requirement the moment one convention is pinned and byte-level test vectors are published.

Note the cost that promotion will carry: implementations cannot use language-native JSON serialization on this object, and every new implementation has to be tested against published byte-level vectors rather than against semantic equality.

### 5.8 Composition with identified schemes

Where an A2A security scheme is also in force on the same connection — an API key, mTLS, an OAuth 2.0 access token — the caller is identified at that layer and this profile adds unlinkability of the *credential*, not anonymity of the *caller*. Privacy properties do not compose additively: a presentation carried alongside an access token bound to a customer account reveals the account, and the zero-knowledge property changes nothing about that. That is what `mode: "augment"` means, and it is defense in depth on an already-attributed call.

The `substitute`/`augment` split in `skillScopes` makes the transition visible in the card rather than buried in server logic. The cost is that the split is also visible to anyone mapping which skills are reachable anonymously.

### 5.9 Verifier collusion: what the construction buys and what it does not

Colluding verifiers cannot link presentations by nullifier value, provided nullifiers are scoped as specified and `H` is preimage- and collision-resistant on an unknown secret: the nullifiers are unrelated. That is the property the construction buys, and it holds.

What collusion still yields: the shared public signals — anchor root and skill index — which link sessions to the precision of `C(Σ)`; timing; network and TLS fingerprints; root-choice behavior; encoding fingerprints; and request contents. A deployment that also faces a network observer should not claim unlinkability against colluding verifiers unless network-layer anonymity is separately provided.

The failure mode worth naming once more: a deployment that scopes nullifiers to a time window without verifier binding gives colluding verifiers in the same window the same nullifier value, which links their sessions with certainty and at zero cost.

---

## 6. Proof system selection

### 6.1 Why the reference implementation uses Groth16

Two properties.

**Constant-size proofs with sub-10 ms verification.** Verification is what sits on the request path at agent fan-out. At the measured 6.4 ms median in-process, a single core sustains roughly 150 verifications per second. That is the number that decides whether any of this is deployable on the server side.

**One statement over committed state.** The credential relation is

```
MerkleInclusion( Poseidon(secret, issuerId, scopeBitmap), path ) == issuerRoot
scopeBitmap[skillIndex] == 1
nullifier      == Poseidon(secret, sessionScope)
requestBinding is constrained
```

Accumulator membership against a root that changes as credentials are revoked, a nullifier derived inside the statement from a secret the verifier never sees, and bitmap indexing that reveals one bit while hiding the rest — jointly, in one proof. That combination is what a general-purpose proof system is for.

### 6.2 Why BBS is faster and is the right default for attribute predicates

BBS signatures (IETF CFRG `draft-irtf-cfrg-bbs-signatures`; W3C Data Integrity BBS Cryptosuites) provide multi-message signatures with selective disclosure and unlinkable proofs derived from a single signature.

**BBS proof generation is on the order of 1–2 ms, against 200 ms for the reference Groth16 circuit — roughly two orders of magnitude — and it requires no trusted setup.** In a discovery phase querying many providers, that is the difference between a negligible prover cost and a visible one, and the absent ceremony removes the largest single barrier to a credible production deployment. The two timing figures come from different implementations and hardware and are indicative rather than a controlled comparison.

Where the required statement is selective disclosure or a simple predicate over signed attributes — "my credential carries a scope that includes capability *C*" — BBS is the recommended profile. Running Groth16 for a workload BBS covers costs the prover time and adds a ceremony for no gain.

BBS costs relative to Groth16: proof size is larger than 128 bytes and grows with the number of undisclosed messages, and predicates beyond attribute disclosure and simple relations require additional machinery.

Three things a BBS profile has to supply that base BBS does not give for free:

- **`requestBinding` carriage.** Supplied as the BBS presentation header, the direct analogue of a public input for binding purposes.
- **A scope-bound pseudonym.** The CFRG work is `draft-irtf-cfrg-bbs-per-verifier-linkability`, developed in the `draft-irtf-cfrg-bbs-pseudonyms` repository; DAA basenames as standardized in ISO/IEC 20008 and shipped in TPM 2.0 are the long-deployed equivalent. The semantic difference matters and the primitive should not be adopted unmodified: a per-verifier pseudonym is *constant* for a given (prover, verifier) pair, which makes every presentation to that verifier linkable across sessions — coarser than the per-context nullifier specified here. A BBS profile binds the pseudonym to a per-session value and documents the resulting scope. That draft is unstable — revised repeatedly, and it may be merged into the blind-signatures work — so the specification cites it informatively and fixes no normative construction; a BBS profile pins the exact revision it implements.
- **A revocation mechanism.** BBS by itself proves possession of a signature, not membership in a current accumulator. A BBS profile binds to either a status list — accepting the index-correlation cost — or a separate ZK accumulator proof, at which point much of the speed advantage is spent. That last clause is the honest reason the Groth16 profile exists at all.

Selection:

| Required statement | Recommended profile |
|---|---|
| Selective disclosure of signed attributes | BBS |
| "Scope includes capability *C*", no unlinkable revocation requirement | BBS + status list |
| Unlinkable presentation with accumulator-based revocation in one statement | Groth16 (or a universal-setup system) |
| Arbitrary predicates over committed state | Groth16 or a universal-setup system |
| Any of the above, where no credible ceremony is available | BBS, or a transparent proof system |

This document takes no position that the Groth16 profile is preferable in general. Where a deployment needs issuer hiding *and* accumulator membership *and* a scope-bound nullifier in one proof, `groth16-bn254` is what this version specifies for it. A future revision may define a BBS-based `#credential` profile; constructions that would support one — accumulator-backed revocation composed with BBS, and per-verifier pseudonym extensions — exist and are moving.

### 6.3 The trusted-setup obligation

Groth16 requires a per-circuit trusted setup: a one-time procedure producing proving and verification keys, generating secret randomness that has to be destroyed. Anyone retaining it can forge proofs for that circuit. Zero-knowledge is unaffected; soundness is destroyed.

**A ceremony distributes trust but does not verify it.** No transcript demonstrates that a contributor destroyed its secret randomness; the security claim is that at least one contributor did. A party retaining the setup randomness can mint credentials for any skill under any root, undetectably, for as long as the circuit is in use. This is a total soundness compromise and it is silent. That is the reason the multi-contributor rule and the published transcript stayed normative when most of the parameter guidance was demoted.

The obligations that follow:

- Run a universal phase-1 (Powers of Tau) ceremony or adopt a published one, and run a circuit-specific phase-2 ceremony for each circuit deployed.
- Publish transcripts that are independently verifiable.
- Do not run production on a single-contributor ceremony. The reference implementation ships one, adequate for benchmarking, identified as such in its own artifacts and in its README.
- Pin the verification key by digest and compare at load. A verifier that resolves a key from anywhere other than local configuration — from the presentation, from a URL in it, from the prover's card — accepts arbitrary statements, because a prover that supplies its own key can run its own setup.
- Provers obtain the common reference string from a verified multi-party transcript and pin it by digest thereafter. Verifying a full transcript is expensive and is normally done once, out of band; the pinned digest is what each proving run checks. A prover that proves against an unverified CRS may be leaking witness material to whoever produced it. This is stated at SHOULD for the prover side because it is unobservable at the verifier; the verifier-side key pinning and the multi-contributor production rule stay normative because they are checkable.
- Any change to depth, `maxSkills`, the hash function, or the statement requires a new phase-2 ceremony and a new parameter set identifier. Circuit parameters are not configuration.

A deployment that cannot run or credibly join a multi-party ceremony should not deploy the Groth16 profile. The alternatives: BBS if attribute predicates suffice; a proof system with a universal setup (PLONK, Halo2) or no setup (STARK-family) if arbitrary predicates are needed. Universal-setup systems move the ceremony obligation from per-circuit to once-per-ecosystem, which is a smaller burden when more than one circuit is deployed, at the cost of larger proofs and slower verification than Groth16.

One further Groth16 property with a protocol consequence: **proofs are re-randomizable.** A party holding a valid proof can produce a different byte string that verifies against the same public signals. Possession of a valid proof is therefore not evidence that the sender holds the witness, and proof bytes are useless as a deduplication key, a replay key, or a session identifier. Detection of a captured-and-resent presentation rests on the challenge, the binding, and the channel.

### 6.4 What a proof-system profile has to define

Adding a proof system to this profile is not a matter of naming an algorithm. A conforming profile specifies: stable identifiers; the credential commitment function, its field or group, and the canonical encoding of each input; what a witness is, its size, and the exact delta-feed encoding it updates from; the ordered list of public inputs and outputs with the canonical byte encoding of each; the canonical byte encoding of roots as they appear in root statements; the nullifier construction, its domain separation, and its scope; the issuer-hiding construction and its cost, if supported; how a verification key is named and how its digest is computed for pinning; setup requirements and how transcripts are verified; wire encoding, media type, and size; how the profile's failure modes map onto the reason registry; and measured constraint count, proving time, verification time, and proof size for the circuit as deployed, with the measurement environment stated and estimates labelled as estimates.

A profile that leaves any public input's encoding implementation-defined does not produce identical bound values across bindings and is not conforming.

---

## 7. Prior art

Nothing in this profile's cryptography is new. The lineage is given here so a reviewer can assess the design against the literature rather than against this document's description of it, and so each mechanism's existing coverage is on the record.

### 7.1 Anonymous credentials

Camenisch and Lysyanskaya, EUROCRYPT 2001, established the construction line — non-transferable anonymous credentials with optional anonymity revocation — and the CRYPTO 2002 dynamic-accumulator paper established revocation over it. IBM's Identity Mixer (Idemix) is the deployed system on that line. What they provide: unlinkable multi-show, selective disclosure, and accumulator-based revocation, formalized and analyzed decades ago. The scope predicate and nullifier in this profile are instances of what that literature already covers.

Hyperledger AnonCreds is the current large deployment of the accumulator approach and is the source of the practical cost data cited in §2.5: tails files at up to roughly 1 GB per revocation registry sized for on the order of 100,000 credentials, growing linearly with registry size, with holder-side retrieval treated as a scalability limit in the specification's own revocation discussion.

### 7.2 Issuer hiding

Bobolz, Eidens, Krenn, Ramacher, and Samelin (CANS 2021, LNCS 13099, pp. 158–178; IACR ePrint 2022/213) formalize issuer-hiding attribute-based credentials in the terms used here. Their construction achieves issuer hiding without a shared aggregated root, which is an advantage over the shared-tree arrangement (Mode B) in this profile and comparable to the trust-set arrangement (Mode C) without the extra Merkle level.

Issuer hiding for BBS-based credentials is an active line — Katz and Šefranek (PKC 2026; ePrint 2025/2080), and further constructions in ePrint 2026/369, 2026/555, and 2026/870 — so a BBS profile does not need a Mode C Merkle level to obtain it.

Set membership over accepted certificate authorities, proved in-circuit, appears in zk-X509 (arXiv:2603.25190) with the same stated motivation about organizational and jurisdictional leakage, and is deployed at conference scale in Zupass's POD/GPC (`isMemberOf` over `signerPublicKey`).

The three arrangements in this profile and their honest trade:

**Mode A — disclosed issuer, one tree per issuer.** Cheapest; no extra constraints. In agent deployments the issuer is typically the caller's vendor, employer, or deployer, so this frequently discloses the organization even though it discloses nothing about the individual agent.

**Mode B — shared tree, many issuers.** Several issuers contribute leaves to one tree; the issuer identifier stays private, so the root identifies the set. Requires no circuit change. Its problem is integrity, not privacy: the operator who assembles the tree can insert leaves of its own construction and mint credentials that verify as any member's. Acceptable only where the tree operator is already trusted to issue on behalf of every member; a poor fit across organizational boundaries, which is why the specification says so at SHOULD NOT — it is a deployment-governance judgement rather than a wire-observable property.

**Mode C — trust-set root over per-issuer roots.** Each issuer maintains and signs its own tree; the verifier recomputes a commitment over the vector of member roots. The issuer root becomes a private witness and the trust-set root becomes the public input. Provided the verifier recomputes the trust-set root itself from signed member statements, no member can produce credentials that verify as another member's, because each member's root is signed by that member's own key. A trust-set root asserted by a set operator without the underlying signed member statements lets the operator insert an issuer, which is why local recomputation stayed normative.

Mode C's integrity floor is the least trustworthy member. Any member can issue a credential in its own tree with any scope bitmap, and under issuer hiding the verifier cannot tell which member did. Admitting an issuer to the set grants it the ability to authorize any skill the set covers, indistinguishably. That is the price of hiding the issuer, and it makes membership a policy decision rather than a configuration detail.

Cost in the circuit: one extra Merkle path. Each level is one Poseidon(2) compression, on the order of 240 R1CS constraints in circomlib, so a depth-4 trust-set level (16 members) adds roughly 1,000 constraints to the reference circuit's 5,597, with proving time expected to scale in proportion. That figure is arithmetic, not a measurement of a compiled Mode C circuit.

Operationally, Mode C has three costs worth stating. Freshness is the minimum over members, so one lagging member degrades the whole set and a set's availability is worse than any individual member's. The trust-set root has to be recomputed whenever any member republishes, and every recomputation invalidates every holder's second-level path — without coordination that is *N* recomputations per interval for *N* members, which the aligned-epoch schedule collapses to one at the cost of requiring loosely synchronized clocks. And eviction of a lagging member is coarse: it cuts off an entire issuer's population at once including holders who did nothing wrong, it is publicly observable, it shrinks the candidate set for everyone remaining, and it is the mechanism by which a set operator can censor a member — which is why membership is published in the clear, so the censorship is at least visible. Eviction also only takes effect when verifiers update the member list in their own card params, so a set operator that does not control those cards can publish an eviction but cannot enforce it.

### 7.3 Nullifiers

Semaphore's external nullifier is the construction this profile's session nullifier follows, and RLN is the rate-limiting extension of it. Semaphore's per-group `merkleTreeDuration` (default one hour) and World ID's root-history expiry (proof-verification default 7,200 seconds, documented range 3,600 to 604,800) are the deployed precedents for the root-history window, arrived at independently and landing in the same order of magnitude as the defaults here.

### 7.4 Signatures and presentation protocols

- `draft-irtf-cfrg-bbs-signatures` and the W3C Data Integrity BBS Cryptosuites — covered in §6.2.
- `draft-irtf-cfrg-bbs-per-verifier-linkability` (BBS Pseudonyms) — a per-verifier pseudonym primitive, unstable, cited informatively.
- OpenID for Verifiable Presentations (OpenID4VP) 1.0 defines how a verifier requests and a wallet delivers verifiable presentations, and requires presentations to be linked to `client_id` and `nonce`.
- SD-JWT (RFC 9901) defines a salted-hash construction for disclosing a chosen subset of a signed token's claims. Its Key Binding JWT commits to `aud`, `nonce`, `iat`, and `sd_hash` — the same class of binding this profile's `requestBinding` obtains, and the construction it is deliberately shaped after. Where the requirement is "show your registration number but not your address," SD-JWT does that well and this profile is the wrong tool. What SD-JWT gives is claim *values* rather than predicates over them, the issuer signature identifies the issuer, and repeated presentations of one token are linkable unless the holder is issued single-use batches — an operational burden proportional to presentation volume.
- `a2aproject/experimental-ext-oid4vp-auth` — prior art for both the interaction pattern this profile uses at first contact and the metadata-keyed-by-URI carriage convention, and the general-purpose credential-presentation extension for A2A. This profile follows both conventions and does not replace or deprecate the extension. The two differ in what the presentation proves and where it travels: an OID4VP presentation discloses selected claim values signed by a named issuer, exchanged in the OID4VP flow itself; a zk-A2A presentation travels in-band as a data `Part` and discloses a predicate plus a scope-bound nullifier. In-band carriage removes an out-of-band dependency and its trust relationship, and means the presentation traverses the A2A message path and whatever logging that path performs. That extension's status is experimental and breaking changes are possible; implementers should read the revision current at implementation time.

### 7.5 Unlinkable tokens

Privacy Pass, RFC 9576 (architecture), RFC 9577 (the HTTP authentication scheme), RFC 9578 (issuance). Covered in §1.2. RFC 9576's warning that each additional partitioning dimension multiplies tracking granularity is the same phenomenon as §4.1's scope tuple, and its advice to bound the number of concurrently active issuance configurations is the same remedy as coarsening skill indices.

The two compose rather than compete: a deployment can accept `PrivateToken` for coarse abuse control and a zk-A2A presentation for per-skill scope.

### 7.6 Status lists and revocation

`draft-ietf-oauth-status-list` (Token Status List) and W3C Bitstring Status List specify compact, cacheable revocation status referenced by index. They solve the adjacent problem and solve it well. A deployment should default to them and adopt the accumulator only where unlinkability across verifiers is an actual requirement.

| | Token Status List / W3C Bitstring Status List | zk-A2A accumulator |
|---|---|---|
| Verifier fetch pattern | whole artifact, scheduled, verifier-local | whole artifact, scheduled, verifier-local |
| Per-presentation issuer contact | none | none |
| Identifier disclosed to verifier | stable index | scope-bound nullifier; no stable index |
| Linkage by colluding verifiers | yes, by index | not through any value carried in the presentation; still possible through nullifier scope, timing, network identifiers, and the enumerable population |
| Holder-side state | none | Merkle path, refreshed per epoch |
| Holder-side cost per presentation | negligible | ~200 ms proving (Groth16 reference profile) |
| Artifact size | compressed bitstring; 131,072 entries ≈ 16 KB uncompressed at 1 bit/entry | 32-byte root; delta feed proportional to churn |
| Status granularity | multi-state via `bits` ∈ {1,2,4,8} | binary |
| Trusted setup | none | per-circuit ceremony under Groth16 |
| Freshness knob | `ttl`, `exp` | `ttl`, `maxRootAgeSeconds` (deliberately the same shape) |
| Standardization | IETF standards-track; W3C Recommendation track | none; this is an experimental draft |
| Small-population privacy | acknowledged failure mode in the specifications themselves | candidate set bounded by non-empty leaf count and by §4 |

Two points cut against this profile and deserve emphasis.

**The index is the whole difference, and status lists are otherwise simpler.** W3C Bitstring Status List recommends a minimum of 131,072 entries unless an ecosystem specification sets a different lower bound, precisely to provide herd privacy, and its privacy considerations acknowledge that correlation risk rises when the issued population is small. A cross-organizational agent ecosystem in its early years is a small population. That is a reason to reason carefully about set sizes in *both* mechanisms, not a reason to assume the accumulator is automatically better.

**Non-membership in a status list can itself be proved in zero knowledge**, by proving that the bit at a private index is 0 against a commitment to the list. That is a legitimate alternative. This profile does not adopt it because the commitment would have to be over the *uncompressed* bit array, and a Merkle commitment over an uncompressed bit array is structurally the same object as the membership tree specified here, with worse locality for witness updates. The two designs converge.

Approaches that attack index correlation without zero knowledge should be evaluated first by any deployment whose requirement is to *reduce* rather than eliminate correlation. CRSet (Hoops, Gebele, Matthes, arXiv:2501.17089) encodes revocation state as a padded Bloom filter cascade in the manner of CRLite (Larisch et al., IEEE S&P 2017), with padding chosen to hide issuer business metrics, and publishes it non-interactively. A cascade of this kind classifies exactly the identifiers known when it was built; misclassification is possible for identifiers outside the sets it was constructed over, which a deployment has to handle if identifiers can be presented that the issuer did not enroll.

The mechanisms compose: one credential, a status list in the identified transacting phase and the accumulator in the anonymous discovery phase, provided the status list index is never disclosed during the anonymous phase. Using both on the same connection defeats the anonymous phase.

ETSI TS 119 615 is the reference for what "warn and pass" looks like when a trusted list's next-update date has passed, and is the closest published analogue to the degraded-acceptance decision in §2.5.

### 7.7 Session binding and hardware attestation

ISO/IEC 18013-5's `SessionTranscript` is the model §2.2 follows and the reason the binding sits at the object model. WebAuthn's `clientDataJSON` (committing to `type`, `challenge`, and `origin`) is the model for binding the peer's name, and WebAuthn/FIDO basic attestation batching is one of the comparison rows in §4.5, with certification guidance putting a batch at 100,000 devices or more. EPID (Brickell and Li) and DAA — ISO/IEC 20008-2 anonymous signatures with a linking base, TPM 2.0 basenames — are the hardware-rooted analogues of the group and pseudonym constructions, and the assumption they make that this profile cannot make is a scarce, non-cloneable holder (§3.6).

RFC 5705 and RFC 8446 §7.5 (TLS exporters) are the channel-binding alternative considered and not adopted (§2.1).

### 7.8 Proof systems and tooling

Groth (EUROCRYPT 2016) for the proof system; Circom, circomlib (Poseidon), and snarkjs 0.7.3 for the reference toolchain; Bowe, Gabizon, and Miers (ePrint 2017/1050) for the Powers of Tau ceremony construction.

### 7.9 Anonymity metrics

Serjantov and Danezis (PET 2002) for the effective-anonymity-set metric used in §4.8, and Díaz, Seys, Claessens, and Preneel (PET 2002) for the parallel formulation. The reason to prefer effective size over raw count is entirely practical: raw counts overstate by more than an order of magnitude whenever the traffic distribution is skewed, and agent traffic distributions are skewed.

---

## 8. Alternatives considered and rejected

Collected here so a reviewer can reopen a decision rather than rediscover it. Each entry names the alternative, why it was attractive, and why it was not taken.

### 8.1 Binding

**TLS exporters (RFC 5705 / RFC 8446 §7.5) as the freshness and audience source.** Attractive because it binds the actual channel rather than a name. Not taken: not exposed by most HTTP client stacks, changes meaning wherever TLS terminates at a proxy or load balancer, and not available identically across A2A's bindings. Where the binding is available, applying it in addition is worth doing.

**ISO 18013-5-style `SessionTranscript` over the serialized transport bytes.** Not taken: A2A has four transports and protobuf serialization is not canonical, so a transcript from one binding does not reproduce under another.

**Binding a literal method name (`message/send`, `SendMessage`, `POST /v1/message:send`).** Not taken: method names differ per binding, so a literal name breaks cross-transport identity. An abstract operation identifier stays fixed even across a future core rename.

**`verifier_id` from an endpoint URL in `supported_interfaces`.** Not taken: `supported_interfaces` is a repeated `AgentInterface`, each with its own `url` and `protocol_binding`, so a multi-transport agent has several endpoint URLs and no one of them is transport-independent. Using one would make `verifier_id` transport-dependent, which is exactly what the construction avoids.

**`verifier_id` from `AgentCard.name` or `provider.organization`.** Not taken: neither is unique.

**`verifier_id` from the gRPC `:authority` or the HTTP `Host` header.** Not taken: not available identically across bindings, and rewritten by proxies.

**`verifier_id` from a TLS certificate or SPKI hash.** Not taken: changes on rotation and at any terminating proxy.

What was taken: the absolute HTTPS well-known Agent Card URL the prover actually fetched, RFC 3986-normalized — the identifier the client demonstrably possessed before it decided to talk to this agent, which is the property that makes WebAuthn's `origin` the right anchor there. With an optional alternative of `"jkt:"` plus the RFC 7638 thumbprint of the card-signing key, which binds to a key rather than a name and survives a domain move, at the cost that rotating the signing key changes `verifier_id` and resets every scope it participates in.

**Reducing a full SHA-256 digest modulo the BN254 scalar field order.** Not taken: introduces non-uniformity. Truncation to 248 bits by zeroing the most significant octet gives no bias, no rejection sampling, and no ambiguity, at a stated cost of 248-bit preimage resistance and roughly 124-bit collision resistance. Collision resistance is the relevant property — a collision on `requestBinding` would let a proof produced for one request be accepted for another — and 124 bits is a comfortable margin for that.

**Poseidon rather than SHA-256 for `sessionScope` and `requestBinding`.** Not taken: both values are computed *outside* the circuit by both parties. The circuit never hashes them, so the in-circuit cost argument for Poseidon does not apply, and SHA-256 is available in every A2A implementation stack without a ZK dependency.

### 8.2 Carriage and placement

**Carrying the challenge in a data `Part`.** Attractive because three of the six source drafts did it. Not taken: the profile's placement rule puts all profile fields in `metadata` keyed by the extension URI and reserves the data `Part` for the proof, which means one lookup retrieves everything the profile owns, and it matches the convention `experimental-ext-oid4vp-auth` already uses.

**Publishing a presentation in `AgentExtension.params`.** Not taken, and this is a security matter rather than a style one. The Agent Card is fetched out of band from the request it would authorize, and at fetch time there is no channel over which to bind the card's contents to a presenter. A presentation published in card params is structurally a bearer artifact: anyone who fetches the card holds it. Presentations belong on the request path.

**A new `SecurityScheme` variant for zk-A2A.** Not taken: adding one is a change to the core schema. Per-skill scope is expressed in `params.skillScopes` instead, and zk-A2A does not appear in `security_schemes` at all.

**Inferring activation from an earlier request in the same context or task.** Attractive because it removes a constant header from every request. Not taken: activation is per request, and a server that infers it verifies presentations on exchanges it did not activate.

**A `proofSystem` scalar plus `circuitId`/`circuitVersion`.** Not taken: one statement can have several parameter sets, and "circuit" is misleading for signature-based systems. An array of proof-system objects keyed by `parameterSetId` is canonical; the scalar is accepted only as a deprecated compatibility form, and rejecting it is conformant.

### 8.3 Nullifier scope

Task scoping and epoch scoping, both analyzed in §3.3, both rejected as the default. A globally scoped epoch nullifier is not merely rejected as a default — it is forbidden, because it hands colluding verifiers cross-organizational linkage with certainty and at zero cost.

### 8.4 Trust anchors and revocation

**Accepting a bare root value as a trust anchor.** Not taken. A root commits to the vector of leaf values at their positions and to nothing else — not the epoch, not the issuer's identity, not the tree depth, not the hash function, not the skill-index mapping, not the time of publication. Those are carried in the signed root statement and are bound by the *signature*, not by the root. A bare field element carries no issuer, no epoch, and no parameters, and a prover that supplies one is asking the verifier to trust the prover's choice of anchor.

**Stapling — the presenting party supplies the signed status artifact.** Attractive because it is how OCSP stapling solves availability. Not taken: the verifier locates the root statement in its own cache, and the presentation's `anchorId` and `rootEpoch` are hints for that lookup rather than evidence of anything. Cached signed statements already deliver the availability property that CRL and status-list caching provide, without accepting an artifact from the party being checked.

**A per-holder witness service.** Not taken as the primary mechanism: it reveals the requested index to the issuer, and if holders fetch immediately before presenting, fetch timing correlates with presentation timing. An issuer offering one also offers the delta feed, and holders use the feed.

**Re-indexing or compacting the tree on revocation.** Not taken: it invalidates every holder's path at once, turning one revocation into a global witness outage.

**Reusing a removed scope index for a different capability.** Not taken: reassignment silently changes the meaning of every outstanding credential, and outstanding credentials are exactly the ones that cannot be recalled. The cost of append-only is a monotonic index space that accumulates dead indices.

**Anchoring roots on a public ledger.** Attractive because it gives a single canonical writer ordering and removes equivocation. Not taken as a requirement or a default: it imposes settlement latency on republication and is frequently refused by enterprise buyers in regulated settings. A deployment may still do it.

**Event-driven republication instead of a heartbeat.** Not taken: republication timing would itself disclose revocation events, and a verifier could not distinguish "nothing has been revoked" from "the issuer has stopped publishing."

**Failing closed on every stale root.** Not taken as the only option: it turns an issuer's publication hiccup into a total outage of the discovery phase, and hands an adversary with network position a denial of service that doubles as a deanonymization lever. Degraded acceptance exists for that case, off by default, with no side effects permitted.

**Proving against the newest accepted root.** Not taken as the recommendation: a prover that always proves against the newest root reveals that it refreshes promptly, and a prover whose witness updates lag consistently is identifiable by its lag across sessions. A fingerprint that persists across sessions erodes the property the profile exists to provide, while the extra exposure from proving against the oldest accepted root is bounded by a window the verifier itself chose.

### 8.5 Statements

**A `#capability` statement (advertised skills backed by an approved model and a committed tool manifest) and a `#policy` statement (task log satisfied the declared policy).** Both exist in the reference implementation as compiled, measured circuits. Neither is in this version of the profile. Server-side attestation — a statement a server makes about *itself* — is a non-goal for v1, and references to undefined statements were removed rather than promoted. This is the largest piece of the reference implementation that the specification deliberately does not cover.

**Multi-statement challenges.** Not taken in this version: a challenge solicits exactly one statement. A verifier requiring more obtains them through separate challenges, at one round trip per statement, and presentations obtained in the same task are linkable to each other by `task_id` regardless of nullifier scope. Whether a later version defines a conjunction, and how the nullifiers of statements presented together relate, is open.

### 8.6 Reporting

**A `ZK_A2A_` prefix on `ErrorInfo.reason` values.** Not taken: the domain already namespaces the reason, and receivers compare the `(domain, reason)` pair regardless.

**Placing the zk-A2A `ErrorInfo` first in the details list.** Not taken, for the SDK behavior documented in §2.3.

**Fine-grained failure reasons to unauthenticated peers by default.** Not taken: reasons naming untrusted or stale anchors, unsupported parameter sets, and index mismatches map verifier policy for a prober, and a reason positively confirming that a nullifier has been seen in a scope leaks exactly the linkage the construction protects. `zk-a2a/attestation-rejected` is the recommended outward default, with the fine-grained reason logged locally.

---

## 9. Measured performance of the reference implementation

### 9.1 Environment

| | |
|---|---|
| Hardware | Apple M4 Pro, 14 cores, 26 GB |
| Platform | darwin 24.5.0 |
| Node | v22.22.3 |
| snarkjs | 0.7.3 |
| Proof system | Groth16 over BN254 |
| Repetitions | 10, after one untimed warm-up proof that is verified before timing begins |

The measurement harness is `scripts/bench.mjs` and the raw output is `build/bench.json`. Every number below comes from that file. Proofs are verified before they are timed, so a circuit that silently accepts a bad witness cannot produce a fast-looking result.

### 9.2 Results

| Circuit | Constraints | Public signals | Prove median | Prove mean | Prove min–max | Verify median | Verify mean | Verify min–max | Proof (JSON) | zkey |
|---|---|---|---|---|---|---|---|---|---|---|
| `credential` | 5,597 | 4 | 200.2 ms | 206.1 ms | 191.2–270.5 ms | 6.40 ms | 7.65 ms | 5.95–16.26 ms | 722 B | 3.3 MB |
| `capability` | 4,133 | 3 | 164.2 ms | 164.6 ms | 163.2–167.3 ms | 7.21 ms | 6.75 ms | 5.66–7.56 ms | 719 B | 2.6 MB |
| `policy` | 7,792 | 2 | 240.5 ms | 247.2 ms | 236.9–284.9 ms | 6.00 ms | 6.66 ms | 5.53–9.94 ms | 722 B | 4.6 MB |

Only the `credential` circuit is in scope for this profile; the other two are measured in the same run and are listed because they establish that verification cost is roughly flat across circuit sizes in this range while proving cost tracks constraint count.

The `credential` circuit as measured is `CredentialAttestation(20, 64)`: depth 20 (capacity 1,048,576 leaves), `maxSkills` 64, public signal vector `(nullifier, issuerRoot, skillIndex, sessionNonce)` — three public inputs and one public output, four signals.

### 9.3 Three caveats that matter more than the numbers

**The 128-byte figure is the compressed proof, and the implementation does not emit it.** 128 bytes is the compressed Groth16 representation over BN254: `A` as a compressed G1 point (32 bytes), `B` as a compressed G2 point (64 bytes), `C` as a compressed G1 point (32 bytes). What the reference implementation actually puts on the wire is the toolchain's JSON proof object, measured at **722 bytes** — about **5.6×** the compressed form. Both numbers are true and they measure different things. Any citation of "128-byte proofs" is a claim about the encoding the specification requires, not about what this code currently produces. The specification's byte-indistinguishability requirement is at SHOULD rather than MUST for precisely this reason, and the gap closes when the flag-bit and byte-order convention is pinned and byte-level test vectors are published.

At 128 bytes the size question is immaterial anyway. Carrying the proof in a `data` `Part` costs roughly a third in size for binary fields, since `google.protobuf.Value` has no bytes type, and buys identical wire semantics on the JSON and gRPC bindings.

**These are in-process library calls, not process invocations.** Both `prove` and `verify` are timed around direct `snarkjs.groth16` calls inside a single Node process, after the zkey and wasm are already resolved from disk. A measurement taken by shelling out to the snarkjs CLI once per proof measures something else: Node startup plus loading a 3.3 MB proving key dominates, and the resulting figure is not a measure of the proof computation. Anyone reproducing these numbers should keep the prover warm; anyone reporting a much larger number should check whether they are measuring process startup.

The corresponding caveat on the verify side is smaller but real. The verify maximum of 16.26 ms against a median of 6.40 ms is JIT warm-up and garbage collection, not variance in the pairing computation. The median is the number to use for capacity planning; the maximum is the number to use when setting the wall-clock bound past which a verification attempt is treated as a rejection rather than a hang.

**The measured circuit is not the specified circuit.** The circuit measured here has three public inputs and one binding value (`sessionNonce`), which the specification splits into `sessionScope` and a separately constrained `requestBinding`, giving five signals. That revision changes the constraint system and requires a new ceremony and a new parameter set identifier. It has not been compiled or measured. Two further deltas are quoted in the specification and are arithmetic rather than measurements: roughly 240 constraints for the rate-limit nullifier (from circomlib's published Poseidon(2) cost) and roughly 1,000 constraints for a depth-4 Mode C trust-set level. Both are labelled as estimates and should be measured before either profile is offered.

### 9.4 What the numbers imply for deployment

**Verification is affordable on the request path.** 6.4 ms median is roughly 150 verifications per second per core. That is the number that decides whether this is deployable server-side, and it is comfortable.

**Every additional public input is free by comparison.** One G1 scalar multiplication, negligible against 6.4 ms. There is no verification-cost argument against binding more values into the statement; the arguments against it are about what the values disclose.

**The denial-of-service asymmetry runs against the prover, about thirtyfold.** A verifier spends 6.4 ms to make a prover spend 200 ms. That is a reason for provers to bound concurrent proving operations and to rate-limit the challenges they accept per verifier.

**The reverse surface is real too, and it is attacker-triggerable without authentication.** 150 verifications per second per core is cheap per call and meaningful in aggregate. Bounding the incoming part size before parsing, and checking the public-signal count against the declared layout *before* invoking the proof verifier, are what keep an unauthenticated party from spending a verifier's cores. Rate-limiting unauthenticated challenge issuance matters for the same reason, since each outstanding challenge costs nonce state.

**Proving cost is per-verifier and parallelizable.** A client shopping 50 providers spends about 10 seconds of proving in total, which parallelizes across providers. Under the BBS profile, where the statement reduces to selective disclosure, that cost falls by roughly two orders of magnitude.

**The zkey is the operational artifact people forget.** 3.3 MB for the credential circuit, loaded once per prover process. It has to be distributed, pinned by digest against the verified ceremony transcript, and kept out of the request path.