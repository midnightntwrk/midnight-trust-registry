# Protocol sequences

These diagrams distinguish a **reference simulator flow** from a production network transaction. The trusted embedding host owns private VP intake, DID/status checks, and Compact submission; the packaged CLI does not supply these ports.

## Apply with a Midnight VP

```mermaid
sequenceDiagram
  autonumber
  actor Applicant
  participant Portal as Applicant portal
  participant API as Trusted API host
  participant DID as DID resolver
  participant VC as VC/VP + status verifier
  participant Store as Private admission store
  Applicant->>Portal: Select role and exact scope
  Portal->>API: Register signed pending application
  API->>DID: Verify applicant authentication key
  API->>Store: Persist pending binding
  Portal->>API: Request one-use challenge
  API-->>Portal: Nonce + challenge commitment
  Applicant->>Portal: Present signed VP
  Portal->>API: Submit VP + challenge
  API->>VC: Verify proof, subject, eligibility, status
  API->>Store: Consume challenge and persist redacted evidence
  API-->>Portal: Signed evidence receipt (no claims)
```

The private routes require applicant authorization, a real resolver, current policy binding, and atomic challenge consumption. Without the injected port they return `503`.

## Govern a scoped grant

```mermaid
sequenceDiagram
  autonumber
  actor Maintainer
  participant API as Trusted API host
  participant Port as Governed action port
  participant Compact as Compact simulator/ledger
  participant Projection as Query projection
  Maintainer->>API: Prepare proposal for exact evidence receipt
  API->>Port: Read current policy, sequence, verifier key
  Port-->>API: Policy-bound digest context
  API-->>Maintainer: Exact context to sign
  Maintainer->>API: Submit distinct external Schnorr signatures
  API->>Port: Recheck context and submit
  Port->>Compact: Verify evidence key, live quorum, signatures
  Compact-->>Port: Proposal event commitment
  Port-->>API: Accepted event hash
  API-->>Maintainer: 202 (not network finality)
  Maintainer->>API: Prepare and sign approve, then activate
  API->>Port: Submit each governed action
  Port->>Compact: Verify and append events
  Compact-->>Projection: Observe committed records/epoch
```

The preimage is invalid if sequence, policy, scope, predecessor, or membership changes before submission. Proposal, authorization, and activation are distinct state transitions.

## Rely on a decision

```mermaid
sequenceDiagram
  autonumber
  actor RelyingParty as Relying party
  participant API as Query API / TRQP
  participant Client as Evidence-verifying client
  participant Anchor as Independent ledger anchor
  RelyingParty->>API: Query DID + role + canonical resource + time
  API-->>RelyingParty: Status + policy + epoch/evidence bundle
  RelyingParty->>Anchor: Obtain accepted finalized epoch
  RelyingParty->>Client: Verify bundle against pinned registry/epoch
  Client-->>RelyingParty: Exact-scope decision or fail closed
```

For a VC, the relying party must also verify the VC signature, holder binding, and credential status. An old active bundle is not proof of current authorization.
