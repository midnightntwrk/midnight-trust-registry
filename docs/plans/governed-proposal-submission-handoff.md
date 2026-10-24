# Governed Proposal Submission Handoff

Status: local reference implementation for the 0.1.0 #77/#58 handoff.

The applicant's accepted VP receipt and the Compact proposal are not one
transaction. A host can lose a response after Compact accepted a proposal, and
an absent record in a lagging view is not proof that the transaction failed.
The optional private submission journal records only role, authorization ID,
evidence commitment, submission state, and event hash. It never stores the
raw VC/VP, nonce, holder data, maintainer signatures, or verifier signature.

For issuer, verifier, auditor, and maintainer proposals the API first checks
the accepted application receipt, recomputes the current Compact action, and
parses supplied signatures. It verifies each maintainer vote over the exact
prepared action and rejects duplicate key IDs before reservation. This
cryptographic preflight does not prove active membership, quorum, or the
evidence-verifier's registered key; Compact still makes those decisions.
Immediately before invoking the Compact-backed
port it reserves the exact `(role, authorization ID, evidence commitment)`
under a cross-process file lock. A second attempt is rejected even if the
first result is unknown. A returned event hash advances the journal to
`submitted`, which still does not establish network finality. A thrown error
leaves `reserved` and returns an explicit 503 uncertain-outcome problem; the
host must not infer that nothing was submitted, even when the underlying port
reported a validation error.

Recovery uses a separately supplied reader that authenticates the finalized
ledger view and returns the role/ID's proposal record. A matching evidence
commitment and event hash advances the journal to `observed`. No observation
leaves it reserved/submitted and does not authorize a retry. A conflicting
ledger record fails closed. A production deployment needs an independently
authenticated Midnight finality reader, durable admission storage, and an
operator procedure for definitively rejected attempts. The simulator reader
is a fixture, not a network-finality source.

Tests cover response loss, process restart, concurrent writers, matching and
conflicting finalized observations, unavailable readers, all five proposal
role keys, and absence of raw presentation/signatures in the file. Recognition
proposals have a separate accreditation/admission workflow but use the same
journal at the Compact submission boundary. The adapter is not wired into the
packaged CLI, which has no network-finality source.

The local issuer circuit now has a provider-backed call primitive in
`packages/trust-registry-integration/src/local-issuer-proposal-call.ts`. It
preflights the current finalized ledger version/context, evidence-verifier key and
signatures, maintainer membership/threshold, and issuer scope, requires a
contract-address-bound finalized ledger reader and a one-attempt journal,
and calls the actual `proposeIssuerAuthorization` circuit through Midnight.js.
The returned event hash must match the precomputed governed event; a mismatch
remains an uncertain journaled outcome requiring independent reconciliation.
In the local 0.1.0 profile, the Compact issuer `policyId` is the governed policy
commitment, not a hash of the human-readable policy identifier. Tests mock the
SDK submission; they are not deployment evidence. The primitive is not
connected to the API or a trusted local finality reader; a caller-supplied
address label alone does not authenticate a ledger read. It does not establish
VP admission by itself, and must not be used to qualify an actor journey
before approved genesis, pinned install bytes, independently authenticated
finalized readback, and post-submission reconciliation are in place.

## Local rotation and capacity

The writable segment is capped at 10,000 attempts and 4 MiB. Capacity
exhaustion returns a typed 503 before submission, including when the eventual
event hash of any outstanding reservation would exceed the byte limit.
`inspectCapacity()` exposes only counts and byte limits; it does not expose
authorization IDs or evidence commitments. An operator should alert before
either writable limit or the 64-archive limit is reached.

Under the journal lock, `rotateObserved(readFinalized)` rechecks every
`observed` attempt against the supplied independently authenticated finalized
reader. A missing or conflicting observation stops rotation without changing
the journal. It then copies only those attempts to a write-once segment and
keeps every `reserved` or `submitted` attempt in a new writable segment. It
syncs the segments before atomically replacing the manifest. A crash before
the manifest replacement leaves unreferenced files,
not a new authorization to submit. A crash afterward uses the committed
manifest; missing, altered, duplicate, or non-observed archived records fail
closed. Every lookup and write searches archived IDs as well as the writable
segment, so rotation does not permit replay. Operators must not delete a
referenced segment, manifest, or lock file to make capacity available. A
lagging `not-observed` read never justifies clearing a reservation.

Local operator procedure:

1. Quiesce submissions and preserve a byte-for-byte private backup of the
   manifest, every referenced segment, and any unresolved original journal.
2. Check `inspectCapacity()` and reconcile pending attempts against an
   independently authenticated finalized reader. Do not retry absent records.
3. Call `rotateObserved(readFinalized)` under the same journal path, then reopen the journal
   and confirm that archived IDs remain non-submittable and pending IDs retain
   their previous state. Resume submissions only after that check passes.
4. If startup fails, stop submissions and restore the complete backup set;
   never create a blank journal at the same path. Inspect unreferenced segment
   files only while quiesced, and remove one only after verifying that no
   committed manifest references it and a backup retains it.

This is a local trusted-storage protocol, not a production distributed lock or
an authenticated network-finality proof. Segment SHA-256 hashes detect
accidental corruption but a party able to rewrite the manifest can rewrite its
hashes. Multi-host use requires one shared filesystem with verified atomic
exclusive-create, rename, and directory durability semantics, or a separate
transactional coordinator. A production host must provide independently
authenticated finalized reads, an approved archive export/recovery procedure,
and a documented operator authorization for definitively rejected attempts
before enabling this adapter. #193 remains open for those gates and full
integration qualification.
