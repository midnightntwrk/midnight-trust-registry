# Actors, roles, and use cases

One organization can hold multiple roles, but each role is a separate scoped grant. Possession of a DID never grants registry privileges by itself.

| Actor | Goal | Authority boundary |
| --- | --- | --- |
| Governance authority | Publish eligibility, disputes, retention, and policy | Policy must be committed; charter does not bypass quorum |
| Bootstrap governor | Initialize registry and first maintainers once | No continuing unilateral admission right |
| Maintainer | Propose, vote, activate, suspend, revoke, archive, publish epochs | Registered DID-bound JubJub key and action-specific quorum; no self-approval |
| Issuer applicant | Request a credential-family/schema/status-method grant | DID control and eligible VC/VP, then governance approval |
| Verifier applicant | Request an exact presentation-request profile | No silent expansion of purpose or disclosure limit |
| Auditor applicant | Request an exact audit mandate profile | Grant does not provide data access |
| Evidence verifier | Verify private VC/VP off-chain and sign a redacted commitment | Must be a governed active key; cannot itself approve membership |
| External authority | Supply accreditation/recognition evidence | Recognition is not local membership or admin rights |
| Holder | Present VC/VP selectively | Registry must not observe presentation activity |
| Relying party | Evaluate current or historical trust evidence | Independently pin and verify authority, policy, epoch, and scope |
| Operator | Run API, indexer, and UI | Transport access does not authorize a ledger mutation |

## Core journeys

1. **Apply:** a DID-bound applicant identifies one role and exact resource, obtains a one-use challenge, submits a signed Midnight VP, and receives a redacted evidence receipt.
2. **Admit:** an authorized evidence verifier signs the eligible result; distinct active maintainers sign the exact policy-bound proposal. Authorization and activation are separate transitions.
3. **Operate:** maintainers may suspend, revoke, or archive a grant with action-specific thresholds. History is appended, not silently rewritten.
4. **Query:** a client selects an epoch and evaluation instant, verifies evidence, and checks that the active grant exactly matches role and scope.
5. **Audit:** a verifier checks the auditor's exact mandate before considering an information request, then applies consent and disclosure policy off-registry.
6. **Recognize:** the local registry evaluates accredited evidence for an external authority and records a scoped recognition. That never converts into a local issuer or verifier authorization.

The full acceptance and rejection matrix is the [0.1.0 reference profile](https://github.com/midnightntwrk/midnight-trust-registry/blob/develop/docs/spec/milestone-0.1.0.md#4-use-cases). The [sequence diagrams](../architecture/flows.md) show how these actors interact with the implemented boundaries.
