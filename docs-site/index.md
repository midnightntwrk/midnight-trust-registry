---
layout: home

hero:
  name: Midnight Trust Registry
  text: Trust decisions with a reason.
  tagline: Governed issuer, verifier, and auditor authorization for the Midnight identity ecosystem.
  actions:
    - theme: brand
      text: Understand the registry
      link: /guide/
    - theme: alt
      text: Run the local demo
      link: /guide/quickstart
    - theme: alt
      text: Operate standalone
      link: /guide/standalone

features:
  - title: Exact scope
    details: A DID is trusted only for an explicitly governed role and resource or request profile.
  - title: Verifiable decisions
    details: Policy commitments, signatures, events, and epochs explain how a decision was made.
  - title: Honest boundaries
    details: Simulator demos and isolated-ledger observations are different; neither alone qualifies a deployed offline release.
---

The registry answers **who may do what, for which scope, under which policy, at which observed state**. It does not issue VCs, resolve DIDs, hold personal data, or replace credential status checks.

For a quick evaluation, run the [simulator demo](./guide/quickstart.md). For a
self-hosted install, follow the [standalone first run](./guide/standalone.md),
which stops at human approval rather than treating the node's own report as
trusted genesis evidence. The [operator acceptance record](https://github.com/midnightntwrk/midnight-trust-registry/blob/milestone-0.1.0/docs/guide/standalone-local-journey.md#operator-acceptance-record)
lists the real deployed actor, egress, recovery, and review cases still needed
for the local 0.1.0 release candidate. No complete deployed actor journey has
been recorded yet.

Read the [0.1.0 reference profile](./guide/status.md), [actors and use cases](./guide/use-cases.md),
and [application-to-decision sequence](./architecture/flows.md) for the model.
