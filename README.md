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
