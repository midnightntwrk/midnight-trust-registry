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

features:
  - title: Exact scope
    details: A DID is trusted only for an explicitly governed role and resource or request profile.
  - title: Verifiable decisions
    details: Policy commitments, signatures, events, and epochs explain how a decision was made.
  - title: Honest boundaries
    details: The reference implementation is simulator-backed; a local API response is not network finality.
---

The registry answers **who may do what, for which scope, under which policy, at which observed state**. It does not issue VCs, resolve DIDs, hold personal data, or replace credential status checks.

The [0.1.0 reference profile](./guide/status.md) is still under construction. Start with the [actors and use cases](./guide/use-cases.md), then follow the [application-to-decision sequence](./architecture/flows.md).
