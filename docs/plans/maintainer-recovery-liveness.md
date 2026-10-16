# Maintainer recovery liveness for 0.1.0

This is the bounded follow-on to issue #200 and the deployment-bound governance
slice in PR #204. It does not define a separate recovery authority.

## Rule

When more than one maintainer is active, each ordinary, emergency, and archival
threshold must be strictly below the active-maintainer count. The target of an
active maintainer suspension, revocation, or archival action cannot contribute
to that action's quorum. A removal must leave a state satisfying the same rule,
except that a single remaining maintainer may use threshold one and cannot be
removed as the last active maintainer.

This deliberately disallows 2-of-2 and 3-of-3 policies. It also means a
2-of-3 policy must first be reduced to 1-of-3 by an authorized policy update
before removing one maintainer, because the resulting 2-of-2 state would
otherwise lack a non-conflicted removal quorum. The update and removal are
separate, signed governance actions with their own policy and event evidence.

This simple rule has a deliberate two-maintainer tradeoff: the only valid
two-active policy is 1-of-2, so either maintainer can remove the other without
its consent. Operators who need independent approval for removal should keep
at least three active maintainers with 2-of-3 and avoid reducing to two except
as a short-lived recovery state. The default threshold is included in the
headroom rule because it authorizes the policy reduction needed before removal;
an all-member default quorum would make that recovery step impossible if one
member is unavailable. A separate recovery authority or a target-specific
removal quorum is deferred rather than implied by this contract.

## Contract and client work

1. Enforce the threshold headroom in the Compact policy validator and after
   every active-maintainer removal. Keep the one-maintainer bootstrap case
   valid, with the existing last-active-maintainer prohibition.
2. Reject an active target's key in the signed removal bundle, including all
   five signer slots. Reuse the existing DID-exclusion check, but make its error
   message applicable to both onboarding and removal.
3. Update the simulator, API prepare/precheck behavior, and operator guidance
   so an impossible policy is rejected before signatures are collected. Do not
   claim that client prechecks replace Compact enforcement.
4. Add contract and end-to-end tests for 2-of-2 and 3-of-3 policy rejection,
   target self-vote, 2-of-3 policy reduction before removal, post-removal
   threshold headroom, and last-maintainer protection. Preserve historical
   policy and event evidence across the two-action sequence.

## Deferred design

A separately authorized recovery authority, timelock, or emergency override
could support all-member thresholds or unavailable co-maintainers in a later
milestone. It needs its own eligibility, key compromise, rotation, conflict of
interest, audit, and network-deployment model. Do not add such a bypass to the
0.1.0 contract by implication.
