# Auditor API Projection (#146)

Status: local implementation plan, stacked on #145. This does not authorize a
public auditor query until the snapshot and API tests pass.

## Boundary

The Compact auditor authorization and local simulator evidence already use a
full canonical request-resource ID. The operator snapshot currently stores
issuer and verifier authorization entries only. An HTTP auditor lookup must
not infer a grant from a verifier row, a bare request-profile ID, or a
caller-supplied evidence bundle.

## Implementation

1. Make `auditorEntries` a required part of the unreleased v1 snapshot and
   summary. Validate each authorization array's role and that each entry's
   evidence identifies the same authorization. Do not add a fallback for old
   snapshots.
2. Populate active and historical auditor fixtures in the deterministic demo
   snapshot. Track auditor submit/approve/activate/suspend/revoke/archive
   operations in mutable workspace replay and include their evidence epochs.
3. Extend CLI list/inspect/export/temporal inspection and report surfaces for
   auditors, without changing TRQP `issue`/`verify` action mapping.
4. Extend the API authorization role to `auditor`. Require a canonical
   composite request-resource ID for verifier and auditor lookup, enforce
   role-disjoint entry selection, and use auditor-specific temporal selection.
5. Test same-subject/same-profile auditor scopes differing in purpose or
   credential-scope commitment, current and historical lookup, lifecycle
   suspension/revocation, and wrong-role/bare-ID substitution. Assert the
   returned evidence matches the requested registry, subject, resource, and
   epoch rather than treating an archived record as a current grant.

Validation: focused CLI/API tests, API and simulator integration, `./run.sh
--light`, audit, and full integration. Keep #142 open until this slice and
independent final-head security review have landed.
