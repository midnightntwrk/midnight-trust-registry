# TRQP decision time and evidence freshness

Status: milestone 0.1.0 reference behavior. See issue #159.

## Time sources

- `snapshot.generatedAt` is operator/export metadata. It is neither the query
  time nor a Midnight consensus timestamp. Existing deterministic fixtures may
  set it to an epoch boundary; consumers MUST NOT use it as a clock.
- An explicit `context.time` is the caller's requested RFC3339 instant. Without
  it, the adapter samples its off-ledger clock once per request. The selected
  instant is returned as `time_evaluated`; only an explicit time is echoed as
  `time_requested`. Equivalent RFC3339 spellings compare by parsed instant.
- Contract epochs are ledger commitments with declared validity windows. The
  contract does not provide a trusted wall clock. A host's projection of
  `effectiveUntil` and other lifecycle timestamps is operational information,
  not proof that wall-clock time passed on-chain.
- The current ledger state is the state of the loaded snapshot, not a historical
  reconstruction at `generatedAt` or at the end of an epoch. A query projects
  its records at the selected instant; a snapshot may be stale relative to
  later ledger changes. Consumers needing stronger freshness must verify a
  fresh ledger anchor or apply their own snapshot freshness policy.

## Decision and proof

- A query MAY answer from a matching record without a bundle valid at the
  selected instant. Its `authorized`/`recognized` field is a snapshot
  projection only, and its message MUST NOT imply cryptographic proof.
- An evidence request MUST return 424 if no bundle for the selected record
  matches an accepted epoch commitment and contains the selected instant in
  that epoch's validity window. An older bundle is not a current proof merely
  because the underlying grant is unchanged. A bundle from a future or
  unaccepted epoch is likewise unavailable.
- Query and evidence use the same record selector and evaluation instant for
  a given request. A 424 evidence response does not negate the query decision;
  it states that the requested proof is unavailable. Clients must not promote
  the query projection into an independently verifiable assertion.
- Epoch window and bundle equality checks compare RFC3339 instants
  semantically. Roots, registry ID, and epoch ID still match byte-for-byte.

## Multiple records for one scope

A newer proposed or authorized renewal does not displace an older active grant.
The latest record that has reached activation or a terminal transition wins;
only when none exists does the latest pending record win. An expired active
record remains selected and yields `false`: older grants do not revive.
Revoked, suspended, superseded, and archived records likewise yield `false`
instead of falling back to an earlier active record. This rule is a projection
over an operator snapshot, not permission to create duplicate live scopes in
the contract.

## Follow-on

Fresh anchoring of unchanged grants, snapshot freshness SLAs, and proof of the
host's evaluation clock are separate capabilities. Until they exist, callers
must expect 424 from the evidence endpoint after the record's bundle epoch
expires, even when a query still projects an active grant.
