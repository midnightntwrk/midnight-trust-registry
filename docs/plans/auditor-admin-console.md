# Auditor Admin Console (#148)

Status: local implementation plan, stacked on #147.

The admin console must fetch the dedicated auditor authorization list and keep
auditor cards separate from verifier cards. It may display the exact governed
request-resource ID, evidence epoch, policy, and lifecycle status. The current
operator snapshot does not carry a complete request-scope preimage, so the UI
must not invent or infer a human-readable purpose or credential scope from the
hash. That richer detail depends on authenticated decision evidence (#79).

Every governed action must require an explicit confirmation naming action,
role, authorization ID, and current status before the mutation request. The
console remains a local-operator surface; confirmation is not authorization,
and API/contract maintainer quorum rules remain decisive. Mutation errors
must be shown rather than converted into a success state. Archived auditor
cards remain inspectable but offer no current trust action.

Tests should cover auditor card grouping/counts, exact role-specific mutation
target, confirm/reject behavior, and the archived evidence label. The local
light gate and focused admin-console/API tests are required before publication.
