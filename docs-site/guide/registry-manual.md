# Registry Manual

The Midnight Trust Registry records scoped trust decisions: **who may do what,
for which resource, under which policy**. Start here to understand the path;
use the applicant portal or maintainer console to take an action.

This is a living product manual, not a legal Terms of Use or a ratified
constitution. The [current capability and limitation record](./status.md)
governs what the 0.1.0 implementation actually supports. The V2 sign-in and
eligibility steps below are a 0.2.0 design, not an available login in 0.1.0.

## Choose your task

| If you want to... | Start with... | What happens next |
| --- | --- | --- |
| Find out whether an organization has a current role | [Browse and query](./use-cases.md) | Check the exact role, scope, source, and time of the reported decision. |
| Request permission to issue credentials, verify presentations, or audit evidence | Applicant portal | Choose the role and exact scope, review the requested proof, submit, then retain the receipt. Submission is not approval. |
| Review a request as a maintainer | Admin review inbox | Check your own authority, the applicant's evidence and scope, and the policy before a governed decision. |
| Practice without changing the ledger | [Local quickstart](./quickstart.md) | Try sample requests and review actions in a local practice workspace. These actions are not ledger grants. |

If you are unsure which role to request: **issuer** means your organization
creates credentials, **verifier** means it checks presentations supplied by
others, and **auditor** means it reviews permitted evidence. A **maintainer**
helps govern the registry; this is a separate authority path, not a general
applicant shortcut. Choosing a card shows requirements; it does not submit a
request or grant permission.

## Identity, eligibility, and permission

These are three different checks. Passing one never silently passes the next.

1. **Sign in:** a short-lived, one-use challenge proves control of a Midnight
   decentralized identifier (DID) authentication key. This is the phase-0
   0.2.0 MVP. It does not assign a registry role and is not a claim of SIOP
   protocol conformance. In the V2 applicant and admin apps, an external DID
   signer and same-origin host can enable this in **Workspace settings**;
   the purposes are distinct and admin sign-in is not voting authority. The short-lived
   session remains in browser memory and is cleared on sign-out or source
   change. A local fixture or packaged 0.1.0 app is not a qualified sign-in host.
2. **Show eligibility:** after reviewing the requester, purpose, and exact
   claims, the actor may provide a verifiable presentation (VP). The verifier
   must check holder binding, issuer trust, status, audience, freshness, and
   the requested role and scope. This is planned 0.2.0 work, not a default
   requirement to disclose a passport, ID, or driver's license at sign-in.
3. **Receive permission:** current registry policy, a governed decision,
   maintainer authority, and any required quorum control the role grant and
   later actions. A valid DID signature or VP alone is not a grant.

If a check fails or its source is unavailable, stop the action. Do not treat a
missing result as a denial by the registry or as a successful authorization.

## Follow a request

1. Choose the role that matches the work: **issuer** issues within an exact
   credential scope; **verifier** checks governed presentations; **auditor**
   reviews permitted evidence; **maintainer** participates in governance under
   a separate authority policy.
2. Review the exact role, resource, scope, intended action, and evidence
   requested before signing or sharing a proof.
3. Submit only through an authenticated host. Keep the redacted receipt and
   its request identifier. An accepted receipt is not an active grant.
4. A maintainer checks the evidence and current policy. Required signatures
   and quorum are separate from the applicant's sign-in or VP.
5. Read back the current result from a qualified source. Distinguish
   **proposed**, **authorized**, **active**, **suspended**, and **revoked**;
   never infer finality from a browser label or fixture response.

For the current implementation and its exact APIs, see the [use cases](./use-cases.md),
[API reference](../api/), and [end-to-end qualification](./end-to-end-testing.md).

## Know your source

The ordinary application should keep endpoint diagnostics and practice
controls in **Workspace settings**. If a practice workspace is active, a
small, plain-language cue must remain visible; hiding it entirely could make
fixture records look like live trust decisions. An API-reported claim is also
not independently authenticated finality. The [source and limitation guide](./status.md)
explains the distinction.
