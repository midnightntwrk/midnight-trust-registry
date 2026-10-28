# Local API Reviewer Trust Anchor

Status: candidate export and exact-byte comparator implemented locally;
protected API enforcement and release qualification remain open.

The local API runtime plan is signed, and its v3 approval chain verifies
genesis, committee, and deployment approval signatures. The plan loader
currently accepts the governance reviewer fingerprint and keyring from API
startup arguments. A replacement plan and approval chain signed by a newly
selected reviewer can therefore be accepted if the startup arguments are
also replaced. The current chain test intentionally demonstrates this case.
Signature validity alone is not proof that the reviewer was approved at first
setup.

The wizard's `export-api-approval-chain` command now emits a private
`api-trust-anchor.candidate.json` beside the exact chain. It pins that chain's
SHA-256, the genesis approval digest, both reviewer fingerprints, and the
source/install/network/genesis/contract identity. This is a review candidate,
not an API trust anchor: the API does not yet require a protected installed
copy, and this producer-side export cannot establish independent finality.
The API package has an opt-in comparator that rejects a self-consistent
replacement chain against the original anchor bytes. The production loader
does not yet read a protected anchor or invoke that comparator; tests of the
comparator must not be counted as installed-runtime enforcement.

For the self-hosted 0.1.0 RC, first setup must produce an operator-protected
trust-anchor record outside the API runtime plan. It must pin the independently
reviewed genesis approval digest and signer fingerprint, the approved
governance reviewer fingerprint, source and install inventory digests, and the
local network/genesis identity. The API must load this record from a protected
installation path, verify its ownership and bytes, and compare both signer
identities and the genesis digest with the signed approval chain before it
accepts a runtime plan. A separate genesis reviewer and governance reviewer
remain supported; the governance approval must reference the pinned genesis
approval digest. Merely supplying another fingerprint on the API command line
must not replace the first-run trust anchor.

Reviewer rotation must use a separate canonical record that identifies the
old and new fingerprints, exact predecessor anchor digest, scope, and
effective time. Both the incumbent reviewer and the newly proposed reviewer
must sign it, and an operator must install it through a controlled offline
restart. Without that record, the API fails closed on a changed reviewer.

Required negative tests include an alternate signer with a self-consistent
replacement plan and chain, changed genesis approval digest, wrong first-run
source or network, a writable or swapped anchor path, and a stale or ambiguous
rotation. A valid two-reviewer first setup and a reviewed rotation also need
positive tests. This is distinct from authenticating finalized deployment and
maintenance transaction inclusion, which remain separate #234/#219 release
evidence. No simulator or injected-provider result closes those gates.
