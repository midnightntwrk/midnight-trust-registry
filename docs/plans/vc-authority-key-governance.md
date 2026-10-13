# Governed VC authority key

Issue #73 requires the key that signs VC signer-authority proofs to be a
governed registry fact, not only a fixture constructor argument. This plan is
for the unreleased 0.1.0 contract; it introduces no compatibility aliases.

## Ledger boundary

The registry records a unique key ID, authority Midnight DID commitment,
absolute method ID commitment, prime-order JubJub public key, consuming
contract address, network commitment, Compact-verifiable domain commitment,
active policy commitment/version, lifecycle status, logical action sequence,
predecessor, and governance event hash. The domain commitment is computed in
the registry from those fields, its own `registryId`, and `kernel.self().bytes`.
For this circuit, the ledger's 32-byte `registryId` MUST already be the
SHA-256 commitment of the canonical external registry ID string. The network,
authority DID, and absolute method ID inputs are likewise SHA-256 commitments;
the two contract addresses are raw 32-byte addresses. The registration API
must construct these fields from canonical strings rather than accept
unverified caller-selected commitments.
The authority key must not share the evidence-verifier-key role or its scope.
All changes use the existing policy-bound maintainer action digest and quorum;
the candidate authority DID cannot vote on its own enrollment.

Registration requires a currently active governance policy, unused historical
key ID, prime-order key, and no other active authority key for that consumer.
The contract accepts 32-byte DID/method/network/consumer commitments but
cannot prove their canonical string preimages; the production registration
boundary must validate those preimages and reject empty or malformed values.
Suspension and revocation use the emergency maintainer threshold. Suspension
prevents new proofs immediately but leaves historical evidence. Rotation creates a new key record
and links the predecessor. It atomically retires the old current key and
activates the new key at one governance sequence; registry overlap is zero.
Revocation is terminal. A
consumer may accept an old proof only under its own pinned-key and monotonic
sequence policy; registry rotation does not silently mutate deployed
consumers.

## Signer and consumer boundary

The signer service reads current finalized key state independently of the
requesting process, verifies its configured DID method/key and domain against
the governed record, then rechecks the finalized grant/epoch quorum, subject
DID state, and authority DID assertion method before releasing a signature.
It rejects suspended, revoked, retired,
wrong-consumer, wrong-network, wrong-method, stale-policy, and stale-sequence
requests. A consumer pins an accepted authority key/domain at deployment and
checks the actual contract address through `kernel.self().bytes`; updates are
explicit, not inferred from a network lookup.
The reference signer wrapper enforces these field comparisons through
injected readers and the published DID 0.7.0 JubJub JWK codec. A production
reader still has to authenticate registry and DID finality, current-key
membership, and numeric governance-policy version; a
fixture returning a typed record is not finality proof.

## Delivery order

1. Add registration and exact ledger query with negative Compact simulator
   tests. No signer integration claim yet.
2. Add suspension/revocation and rotation with zero-overlap retirement
   semantics, historical evidence, and policy-bound quorum tests.
3. Add trusted current-key reader and signer-gate integration, then exercise
   issuer/verifier proofs through the compiled consumer.
4. Run focused tests, `./run.sh --light`, `./run.sh integration`, audit, and
   independent review before publishing the stacked PR.

No wall-clock timestamp is used for key validity. All windows use committed
governance sequences and independently accepted epoch evidence.
