# What the registry does

The Midnight Trust Registry is a governed directory of **scoped trust decisions**, not a list of DIDs that are trusted for every purpose. It records authorization for issuers, verifiers, and auditors; maintains the maintainer quorum that makes those decisions; and records scoped recognition of external authorities. An authorization is meaningful only with its registry, role, resource, lifecycle state, policy, and epoch evidence.

## Six-layer view

| Layer | Responsibility | In this repository |
| --- | --- | --- |
| Governance | Charter, eligibility, voting, emergency and retention policy | Policy snapshots and Compact commitments |
| Federation | External authority metadata and trust chains | Explicit scoped recognition; no automatic transitive trust |
| Registry | Authorized entities and their lifecycle | Compact ledger and domain model |
| Query | Discover and evaluate decisions | Client, local HTTP API, TRQP adapter |
| Credential | VC/VP proofs and status | Consumed from Midnight VC packages, not stored here |
| DID | Party identity and assertion keys | Consumed from Midnight DID packages, not managed here |

## A trust decision is not a VC proof

To accept a credential, a verifier still checks the credential signature, holder binding, status/revocation, and policy. The registry contributes the issuer's scoped authorization at the relevant decision time. To accept a presentation request, a holder or service can check the verifier's exact request-profile authorization. An auditor grant lets a verifier consider a mandate; it does **not** permit blanket access to holder data.

The default identity profile is `did:midnight` with contract-facing JubJub Schnorr signatures. Other DID methods and key types are extension points requiring explicit adapters and policy; the current Compact contract does not natively verify Ed25519, secp256k1, or P-256.

## Where to go next

- [Run a local demo](./quickstart.md) to see a fixture-backed journey.
- [Read the actor matrix](./use-cases.md) before designing an integration.
- [Inspect the domain model](../model/index.md) for exact scope and lifecycle rules.
- [Check implementation status](./status.md) before relying on a feature.

The normative long-form documents remain in the repository's [`docs/spec`](https://github.com/midnightntwrk/midnight-trust-registry/tree/develop/docs/spec) directory. This site is an engineer-friendly guide to that profile and to the current code.
