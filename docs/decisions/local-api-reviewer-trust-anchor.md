# Local API Reviewer Trust Anchor

Status: candidate export and API loader enforcement implemented locally;
installed-runtime verification, reviewer rotation, and release qualification remain open.

The local API runtime plan is signed, and its v3 approval chain verifies
genesis, committee, and deployment approval signatures. The plan loader also
accepts the governance reviewer fingerprint and keyring from API startup
arguments. Without an independently installed anchor, a replacement plan and
approval chain signed by a newly selected reviewer could be accepted if those
arguments were also replaced. Signature validity alone is not proof that the
reviewer was approved at first setup.

The wizard's `export-api-approval-chain` command now emits a private
`api-trust-anchor.candidate.json` beside the exact chain. It pins that chain's
SHA-256, the genesis approval digest, both reviewer fingerprints, and the
source/install/network/genesis/contract identity. This is a review candidate,
not an API trust anchor until an independently reviewed copy is installed.
This producer-side export cannot establish independent finality. The v3 API
loader requires `TR_API_TRUST_ANCHOR_PATH`, reads the protected installed
copy, and compares it to the approval chain before accepting the plan. It
rejects a self-consistent replacement chain against the original anchor.
The protected-file reader requires a root-owned regular file under root-owned,
non-group/world-writable ancestors, with no symlink or hard-link replacement.
The file must live outside the API's writable-to-the-operator approval bind
mount. Unit tests of the reader and loader are not installed-runtime evidence.

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
