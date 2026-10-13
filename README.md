# zk-A2A

zk-A2A is an independent experimental authorization profile for the
[Agent2Agent (A2A) protocol](https://github.com/a2aproject/A2A).

It lets a client agent prove that it holds a valid, unrevoked credential whose
scope covers the A2A skill it wants to invoke, without revealing the agent's
identity, credential, issuer, or unrelated authorization scopes.

The intended use is early-stage discovery and quoting between organizations:
anonymous while evaluating providers, identified when a transaction begins.

## Status

This project is an independent draft. It has not been reviewed, sponsored, or
adopted by the A2A project or the Linux Foundation.

- [Extension specification](spec/spec.md)
- [Design rationale and threat analysis](spec/rationale.md)
- Reference implementation: in progress on the
  `implementation/credential-v2` branch

## Reference implementation

The development branch contains the Circom `credential-v2` statement,
session-scope and request-binding derivations, a verifier-side challenge API, deterministic vectors,
negative tests, and a benchmark. It requires Node.js 22, Circom 2.1.8, and npm.

```bash
npm install
npm run build:circuit
npm run setup:dev   # development keys only; not a production ceremony
npm run vectors
npm run prove
npm test
npm run bench
```

The circuit proves that a hidden credential leaf belongs to the accepted
Merkle root and that its hidden scope bitmap authorizes the requested skill.
It emits a context-stable nullifier and a fresh request tag. The verifier
reconstructs the root, skill index, session scope, and request binding from its
own trusted state before verifying the proof.

The project composes established cryptographic techniques. Its focus is their
binding to A2A's extension negotiation, task lifecycle, transport-independent
object model, revocation state, and privacy constraints.

## Community path

The planned next step is an Extension Proposal issue in
`a2aproject/A2A`, requesting community review and a maintainer sponsor for an
`experimental-ext-zk-a2a` repository under the A2A organization.

## Author

Reza Ramezan

## License

Apache License 2.0.
