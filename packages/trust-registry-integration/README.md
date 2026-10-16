# Trust Registry Integration

Integration scenarios for `midnight-trust-registry`.

Current coverage:

- `createRpcFinalizedCheckpointSource` checks a configured public network's
  node RPC genesis against an independently approved pin, then reads its
  finalized head. `createCheckpointedDeploymentActionReader` queries the
  generated Trust Registry ledger at that block hash and supplies the
  deployment-signing preflight. `createPublicNetworkDeploymentActionReader`
  wires both to the published Midnight indexer provider using configured
  HTTPS/WSS endpoints. These are read-only components: the host must
  trust the node for finality, protect RPC credentials, and independently pin
  the network/genesis pair. Mocked provider tests and a successful RPC probe
  do not qualify a public-network deployment; wallet funding, deployment,
  finalized constructor readback, and replay checks remain #200 work.

- Application VP intake now requires issuer eligibility to return a full
  governed issuer status-policy binding. The reference trusted-reader adapter
  checks an active finalized issuer decision, the credential issuer's DID
  assertion key, and the status-registry ID before the signed status-attestation
  source receives that binding and the one-use challenge. The local fixture
  commits the verified signed status statement, authority DID state version,
  and governed issuer status-policy binding into redacted application evidence.
  The fixture retains the exact signed witness for private audit because
  re-signing the same statement can produce different proof bytes. The
  governed-registry demo audits all four applicant roles and rejects a
  substituted issuer policy without returning the witness publicly. This
  commitment is not a public non-revocation proof. The fixture uses a
  deterministic non-governed grant and attestation fetcher; network
  finality and an independent live status-registry proof are still required
  for production non-revocation claims.
  A simulator composition test now signs a fixture VC/VP with the same issuer
  key as a verified active grant, uses that grant's status-policy preimage for
  challenge-bound status verification, and rejects a suspended current grant.
  `createHttpApplicationStatusSource` can fetch the same signed attestation
  from a configured HTTPS status authority endpoint (loopback HTTP is only for
  local demos). It POSTs the registry, handle, credential-body root, and
  challenge commitments with no raw credential, disables cache and redirects,
  and then applies the same governed-binding, DID assertion-key signature,
  challenge, active-status, and freshness checks. Network/5xx/429 failures are
  retryable dependency outages; 4xx, malformed, and invalid signed answers
  never establish eligibility. The transport does not authenticate Midnight
  finality or provide an independent live status-registry proof.

- local simulator trust-decision flows for issuer, verifier, and recognition
- `prepareIssuerProposalAction`/`executeIssuerProposalWithSignatures` and
  `prepareIssuerDecisionAction`/`executeIssuerDecisionWithSignatures` expose
  policy-bound Compact digest inputs and accept explicit maintainer signatures.
  Proposal also requires a separate evidence-verifier signature. The focused
  integration test uses two distinct non-bootstrap maintainers under a 2-of-3
  policy and rejects insufficient, duplicate, stale, wrong-policy, and
  wrong-evidence-verifier bundles. The API's optional governed-action port can
  submit external approval/activation signatures to this simulator path;
  proposal and production network submission still need a deployable adapter.
  Fixture-driven issuer helpers still sign internally.
  Run `pnpm --filter @midnight-ntwrk/trust-registry-integration exec vitest run
  src/test/external-issuer-signers.integration.test.ts` to reproduce it.
- `prepareVerifierProposalAction`/`executeVerifierProposalWithSignatures` and
  `prepareVerifierDecisionAction`/`executeVerifierDecisionWithSignatures` expose
  the exact request-profile proposal and lifecycle digests to external
  maintainers. The simulator test requires two distinct active signatures at
  every transition and rejects wrong scope, unknown or duplicate signer,
  policy substitution, and stale signatures without advancing governance.
  It checks the resulting active verifier evidence bundle independently. This
  is not yet a public verifier application or HTTP action route.
- Auditor proposal and decision actions have the same explicit 2-of-3 signing
  boundary, but retain an auditor-only mandate scope and request-profile ID.
  The focused test rejects substituted mandates, duplicate/unknown signers,
  policy substitution, and stale lifecycle signatures, then independently
  verifies the active auditor bundle. It does not authorize blanket access to
  holder presentations or make an auditor grant interchangeable with a
  verifier grant.
- External-authority recognition exposes caller-signed proposal and decision
  digests with the recognized authority DID, external registry, and exact
  resource scope bound into the Compact action. The 2-of-3 simulator test
  rejects insufficient, duplicate, substituted-authority, wrong-policy, and
  stale bundles, then verifies the active recognition evidence. Recognition
  is not a local issuer, verifier, auditor, or maintainer membership grant;
  the demo evidence hash is a fixture, not third-party accreditation proof.
  `prepareRecognitionProposalFromAuthorityAssertion` is the distinct
  Midnight-DID-backed path: it verifies the authority's assertion-method
  JubJub signature over the exact target registry, recognition ID, external
  registry, scope, challenge, and bounded validity interval, then commits the
  signed envelope, observed DID version, and evaluation instant as proposal
  evidence. `executeRecognitionProposalWithSignatures` takes that prepared
  context plus separate evidence-verifier and maintainer signatures; it
  refuses stale or substituted contexts. The test uses a fixture DID ledger
  and fixture-held evidence-verifier key. It does not validate the referenced
  accreditation, consume a one-use challenge, support `did:web`, or establish
  network finality. A production intake must supply those boundaries before
  exposing this as external-registry accreditation.
- Maintainer onboarding exposes prepared proposal, approval, and activation
  digests and accepts signatures from existing maintainers at each transition.
  The 2-of-3 simulator test rejects insufficient, duplicate, candidate
  self-voting, wrong-policy, and stale signatures without advancing governance,
  then confirms the activated candidate can co-sign a later issuer action.
  Fixture helpers still sign internally; production signing and network
  submission are not provided by this simulator harness.
- anchored epoch evidence validation. The simulator now retains the complete
  ordered signature witness for epochs it publishes and checks that its event
  hash matches the Compact record before returning it. A two-maintainer test
  verifies both signatures against the contract's maintainer public keys and
  the on-ledger publication event, and rejects missing, reordered, or changed
  signatures. The contract stores the first signature and signer-set event
  hash, not every co-signature. This session-local witness does not authenticate
  a network transaction, historical maintainer state, or finality; production
  consumers must obtain those independently.
- A decision-evidence composition test combines the actual simulator issuer
  grant, policy and Merkle root, retained two-signer publication witness, and
  a DID Document resolved by the published Midnight DID package. It rejects a
  removed issuer assertion relationship and a later suspended grant. The
  transaction and block references are explicit simulator placeholders, not
  independently accepted network anchors. The same test now creates a VC
  descriptor from trusted-reader results and signs a domain-bound authority
  proof with a fixture key; neither step establishes production finality.
- DID-backed resolution of trusted `did:midnight` subjects through official
  `midnight-did` helpers
- VC-backed issuer-descriptor construction using the published
  `@midnight-ntwrk/credential-compact` and
  `@midnight-ntwrk/credential-did-midnight` packages after TR bundle and DID
  method verification. This is a candidate descriptor, not a live
  cross-contract trust anchor. The bundle's `referencedStatusRegistryId` is
  metadata outside the signed authorization leaf and must not be treated as
  authenticated status-policy evidence. The VC scope is derived from the
  verified registry scope, never supplied as a separate caller-selected hash.
  Issuer package and schema IDs are SHA-256 of respectively
  `tr:vc-schema-package:v1:` plus the exact family ID and
  `tr:vc-schema-id:v1:` plus the exact schema ID. Only `major.minor.0` with
  major 1..65535 and minor 0..65535 can map to VC `SchemaRef`. Verifier request
  scope is the canonical 32-byte registry request-scope commitment; the signed
  request must use that same value. Governed VC schema enrollment, anchored
  status policy, and live revocation checks remain separate work.
- `issueVcSignerAuthorizationFromTrustedDecision` re-reads current finalized
  registry and DID state through caller-supplied trusted readers, maps their
  verified decision to the VC descriptor, requests a proof from an injected
  authority signer, then validates it with VC's native
  `assertValidSignerAuthorizationProof`. The signer port must independently
  authorize the request; this layer never handles the authority secret.
  The authority domain is Compact `persistentHash<Vector<7, Bytes<32>>>` of
  `pad(32, "tr:vc-authority-domain:v1")`, SHA-256 of network ID, raw consumer
  contract address, SHA-256 of registry ID, raw registry contract address,
  SHA-256 of authority DID, and SHA-256 of absolute authority method ID.
  Contract addresses are lowercase `0x`-prefixed 32-byte hex, and the method
  is an absolute Midnight DID fragment. The consumer recomputes this domain
  from constructor-pinned fields and checks the pinned consumer address
  against `kernel.self().bytes` on installation. It must provide an authenticated prior
  descriptor or explicit `null` on first install. The local test rejects
  wrong domain, key, method, scope, sequence, DID rollback,
  revoked-to-active replay, and cross-deployment replay. A separate Compact
  consumer fixture pins authority in constructor-initialized ledger state,
  installs monotonic descriptors, checks a genuinely signed issuer credential
  at the schema-signer boundary, rejects a forged credential signature, and
  checks a signed verifier request. Its issuer circuit does not authorize a
  credential definition or status method. A product claiming full issuer
  trust must separately verify those against the same governed grant and
  credential. Both issuer and verifier descriptors derive from simulator
  grants, epoch witnesses, and resolved DID methods. Readers and signer remain
  local fixtures; production finality, governed external VC schema enrollment,
  production finalized authority-key reads and durable deployed consumer
  state remain open.
- `resolveCompactHistoricalEpochAnchor` projects an epoch record, committed
  policy version, and publication signer from a caller-authenticated finalized
  Compact ledger view. The caller supplies the registry and epoch IDs, policy
  version, and an authenticated sequence-to-time mapping; wrong format,
  registry, epoch, policy root, or signer record fails closed. The native
  historical HTTP verifier then checks the API claim against this context.
  This adapter does not fetch network state, establish finality, prove a
  canonical per-statement epoch selection, or derive wall-clock time from
  Midnight counters. Simulator demos exercise the projection with local
  ledger state only.
- `createQuorumGatedVcAuthoritySigner` is a signer-side port wrapper. It uses
  its own trusted registry/DID readers to recheck current finalized quorum and
  method state, then requires an independent finalized current VC authority-key
  read before invoking key custody. The key ID, authority DID/method, network,
  consumer, domain, public key, policy commitment, and effective sequence must
  match the configured anchor and descriptor. The read returns one finalized
  snapshot containing registry ID, current policy commitment and numeric
  version, and current key; a key enrolled under an older policy version is
  refused. A suspended or substituted key,
  stale grant, or substituted root never reaches the signing callback. The
  reader must authenticate the exact registry contract and finality; the
  descriptor's semantic policy label
  is not that numeric version. Fixture readers do not establish network
  finality or production key custody.
- `prepareVcAuthorityKeyRegistration` validates the canonical Midnight DID,
  absolute method, network, consumer address, and exact target registry ID and
  contract address before deriving the Compact action payload for quorum
  signatures. The local harness registers that payload in simulator ledger
  state and confirms suspension blocks the signer. This is action preparation,
  not finalized network submission or a trusted finalized-key reader.
- a clean-checkout Compact composition probe that imports the published
  `credential-compact` module through its npm export, derives VC and VP body
  roots, accepts matching envelope linkage, and rejects mismatched schema,
  claim roots, or issuer methods. The upstream generic relation deliberately
  does not compare holder bindings; the application evidence profile must check
  them separately. The probe tests claim-root, issuer-method, and schema links,
  but does not assert that the generic relation accepts a holder mismatch.
  Run it with `pnpm run test:light` in this package. This is a
  compiler/runtime compatibility and typed-envelope test, not a proof of
  applicant eligibility, issuer authorization, or live credential status.
- a fixture-backed application VP verifier port using published VC 0.2.0
  proof circuits and DID resolution. It verifies issuer/holder method binding,
  issuance and presentation signatures, nonce, holder binding, proof time,
  and status-reference structure, then calls explicit trusted adapters for
  credential-body binding, issuer authorization, live status, and role claims.
  The scenario fixture serializes both proofs into canonical JSON and derives
  body roots from the submitted credential and presentation body strings;
  changing either submitted body or a proof signature fails verification.
  The signed fixture presentation body names the credential body root and
  subject DID; a validly signed presentation naming a different credential is
  rejected before eligibility checks.
  The fixture's role scope, expiry, holder, status registry, handle, and
  authority method are read from
  the signed credential body, and its claims callback uses that observed scope
  for issuer, verifier, auditor, and maintainer applications. Issuer eligibility
  and live status are still fixture-controlled answers, not production trust
  or revocation determinations. The test-family status decision must match the
  signed registry, handle, and authority method and be active and fresh; tests
  reject revoked, mismatched, and stale decisions. No authenticated external
  status witness is verified here.
  The body-binding adapter is responsible for establishing that the holder,
  status, expiry, and role claims came from the signed credential body root;
  the published generic proof circuits alone do not establish that relation.
  No production credential-family adapter is provided in this slice, so this
  fixture-backed port must not be exposed as a public eligibility verifier.
  The role-claims adapter is not passed the requested scope and
  must return the scope commitment derived from claims bound to the verified
  credential body root; echoing the requested scope is not sufficient. The
  port rejects a different attested scope. It allows 60 seconds of future
  proof-clock skew, accepts presentations at most five minutes old, and caps
  evidence validity at the earliest of credential expiry, status validity,
  and 24 hours. The port returns only
  redacted commitment-sized results. It is not a public intake route or a
  standalone non-revocation verifier; callers must supply trustworthy family
  body roots and all four family assertions. Retryable DID/status dependency
  outages produce a redacted `unavailable` result rather than an eligibility
  denial; adapters must signal their own infrastructure outages explicitly.
  Run its focused tests with
  `pnpm --filter @midnight-ntwrk/trust-registry-integration exec vitest run src/test/application-vp-verifier.integration.test.ts`.
- `createApplicationVpIntakePorts` supplies the existing API one-use intake
  with published VC/VP verification and DID-bound signing/verification
  callbacks. It matches the configured signer key to its Midnight DID
  assertion method and rejects an invalid signature. The API intake still
  owns challenge consumption, authorized-verifier lookup, canonical envelope
  construction, and proposal submission. The family adapter must authenticate
  credential claims and status; these ports do not make the resolver trusted,
  establish governed key membership, or create a public route.

The repository pins the compiler in `.compact-version` and Nix, and pins the
runtime in `contracts/trust-registry/package.json`. The probe
resolves the npm-exported `composable.compact` directory as a compiler include
path; no VC source or generated output is vendored into this repository. Its
generated module uses the probe package's dev dependency on Compact runtime;
direct consumers pin that runtime exactly. The installed identity runtime gate
checks published DID/VC package requirements and their resolved runtime before
running the probe.
