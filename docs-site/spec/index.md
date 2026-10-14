# Specification and conformance

This site explains the implementation, but the **canonical requirements** remain in the repository. Read these in order:

1. [0.1.0 reference profile](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/milestone-0.1.0.md): actor use cases, required rejection cases, scope, history, and release gate. It takes precedence for this milestone.
2. [General Trust Registry specification](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/trust-registry.md): longer-term v1 purpose, records, contract/query boundaries, and acceptance criteria.
3. [Application evidence protocol](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/application-evidence.md): canonical redacted result and signature boundary.
4. [TRQP time and evidence](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/trqp-time-and-evidence.md): epoch selection, historical evidence, and fail-closed query behavior.
5. [Issuer status-policy binding](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/issuer-status-policy-binding.md): issuer grant and credential status-policy relationship.
6. [Architecture decisions](https://github.com/midnightntwrk/midnight-trust-registry/tree/develop/docs/decisions): policy snapshots, canonical scope IDs, signed mutation intents, and other settled boundaries.

`MUST` in the 0.1.0 profile is a **target acceptance requirement**, not a claim that every path is deployed. [Implementation status](../guide/status.md) distinguishes simulator-backed code, optional trusted ports, and unfinished production work. In particular, a saved API snapshot and a local Compact simulator do not establish network finality.

## External references

These sources inform the model or interoperability mapping; none is automatically incorporated as a complete on-chain protocol:

- [ToIP Trust Registry V1 Specification](https://github.com/trustoverip/tswg-trust-registry-tf/blob/main/v1/docs/ToIP%20Trust%20Registry%20V1%20Specification.md) and [ToIP Trust Registry Protocol](https://trustoverip.github.io/tswg-trust-registry-protocol/approved/).
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) and [OpenID Federation for Wallet Architectures](https://openid.net/specs/openid-federation-wallet-1_0.html).
- [Governance Framework for Issuer Identity Registries](https://digitalcredentials.mit.edu/docs/Governance-Framework-for-Issuer-Identity-Registries.pdf).
- [zkMe Web3 zk-Credential Network whitepaper](https://www.zk.me/zkMe_The%20Web3%20zk-Credential%20Network.pdf).
- [Kanon VDR requirements](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/research/trust-registry-requirements-memo.md), summarized publicly in the repository memo without reproducing the internal PDF.
- [Bottom-up Trust Registry in Self Sovereign Identity](https://doi.org/10.48550/arXiv.2208.04624).
- [GI registry research paper](https://dl.gi.de/server/api/core/bitstreams/d91fcb27-0129-499f-871d-c3b8ac336b63/content) and [Fraunhofer registry research paper](https://publica-rest.fraunhofer.de/server/api/core/bitstreams/99ea77d3-e321-472d-9431-c43ead2e56da/content).

The OpenID and TRQP adapters are projections, not transitive trust decisions. See [recognition and interoperability](../model/interoperability.md) for the required local policy/anchor boundary.
