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
parses supplied signatures. Immediately before invoking the Compact-backed
port it reserves the exact `(role, authorization ID, evidence commitment)`
under a cross-process file lock. A second attempt is rejected even if the
first result is unknown. A returned event hash advances the journal to
`submitted`, which still does not establish network finality. A thrown error
leaves `reserved`; the host must not infer that nothing was submitted.

Recovery uses a separately supplied reader that authenticates the finalized
ledger view and returns the role/ID's proposal record. A matching evidence
commitment and event hash advances the journal to `observed`. No observation
leaves it reserved/submitted and does not authorize a retry. A conflicting
ledger record fails closed. A production deployment needs an independently
authenticated Midnight finality reader, durable admission storage, and an
operator procedure for definitively rejected attempts. The simulator reader
is a fixture, not a network-finality source.

Tests must cover response loss, process restart, concurrent writers, matching
and conflicting finalized observations, unavailable readers, all four
proposal role keys, and absence of raw presentation/signatures in the file.
Recognition proposals use a separate accreditation/admission workflow and
are not covered by this journal. The adapter is not wired into the packaged
CLI, which has no network-finality source.
