# Trusted Registry Requirements Memo

## Scope

This memo extracts actionable Trusted Registry requirements from the source set below, with emphasis on smart-contract boundaries, authorization rules, verifier/issuer workflows, and evidence needed for long-term credential verification.

## Source Set

- Kanon VDR blockchain requirements PDF (internal research input)
- MIT Digital Credentials Consortium / Credential Engine governance PDF: `https://digitalcredentials.mit.edu/docs/Governance-Framework-for-Issuer-Identity-Registries.pdf`
- `Bottom-up Trust Registry in Self Sovereign Identity`: `https://www.iog.io/papers/bottom-up-trust-registry-in-self-sovereign-identity`
- `Bottom-up Trust Registry in Self Sovereign Identity` DOI: `https://doi.org/10.48550/arXiv.2208.04624`
- `A Note on the Blockchain Trilemma for Decentralized Identity: Learning from Experiments with Hyperledger Indy` DOI: `https://doi.org/10.48550/arXiv.2204.05784`

Note: the two academic sources above are the registry-focused papers used for this memo. They are the strongest match for the user-referenced registry papers and were used where they materially sharpen contract or workflow requirements.

## Reusable Terminology

- `initial trust registry`
- `trust registry DID`
- `credential definition DID`
- `revocation registry`
- `graduated disclosure`
- `policy_uri`
- `trust levels or scales`
- `negative attestations`
- `periodic reviews`
- `retention and archival`
- `tamper-proof storage`
- `actionable state`
- `determine stability of state`
- `ongoing fairness`
- `provide privacy for organizations`
- `maintainers`
- `epoch`
- `merkle tree root`
- `threshold score`
- `non-repudiation`

## Contract Design Implications

- Model the system as separate contract surfaces, not one monolith: `root governance registry`, `issuer/schema authorization registry`, `status/revocation registry`, `proposal/voting contract`, and optionally a `public anchor/commitment contract` for private or off-chain state.
- Keep high-churn status data separate from slow-moving governance data. The sources consistently treat authorization, metadata, and revocation as different operational loads.
- Preserve historical state in append-only form where it affects later verification: prior keys, prior authorized DIDs, authorization timestamps, revocation timestamps, and archival records all matter after issuance.
- Prefer privacy-preserving verification patterns that do not require issuer “calling home” during presentation verification.

## Functional Requirements

- `FR-1` The registry must support a root or `initial trust registry` that authorizes creation of new trust registries and schemas. This is the top-level trust gate for registry expansion. Source: Kanon.
- `FR-2` The registry must expose explicit authorization state for writers and governors: current authorized DIDs, prior authorized DIDs, authorization timestamps, and revocation timestamps. Source: Kanon.
- `FR-3` Public issuer identity must be represented by a DID, preferably on-chain, with a resolvable DID document. The DID document should carry at least: unique ID, SSI agent endpoint, routing keys, current public key, past public keys, legal name, organization metadata, participating trust registries, and logo URL. Source: Kanon.
- `FR-4` Schema records must be first-class registry objects with stable identifiers and lineage. Minimum fields: schema DID, creator DID, writer DID, creator and writer signatures, governing trust registry reference, schema name/version, attribute list, timestamp, and metadata. Source: Kanon.
- `FR-5` Credential definitions must also be first-class registry objects with lineage and status linkage. Minimum fields: credential definition DID, name/version, signature type, source schema DID, creator DID, writer DID, creator and writer signatures, attribute signatures, timestamp, metadata, and linked revocation registry. Source: Kanon.
- `FR-6` The trust registry must support role-scoped authorization mappings, at minimum for creators and readers/verifiers. Reader records should support allowed attributes, allowed predicates, and disclosure policy. Source: Kanon.
- `FR-7` The trust registry should support `graduated disclosure` as a reusable policy abstraction. That means named disclosure levels plus default attribute/predicate policies for unlisted readers. Source: Kanon.
- `FR-8` Registry metadata should include governance and service-discovery material that applications can consume directly: charter, endpoint, logo, and a governance-policy link such as `policy_uri`. Sources: Kanon, MIT governance PDF.
- `FR-9` The registry must expose machine-readable retrieval methods, and ideally human-readable ones too, for issuer and registry data. Sources: MIT governance PDF, Kanon.
- `FR-10` Verification infrastructure must allow external applications to validate both issuer signatures and registry signatures or anchors over registry records. Source: MIT governance PDF.
- `FR-11` The registry should support tamper-evident or tamper-proof storage semantics such as append-only logs, blockchain records, or anchored commitments. Source: MIT governance PDF.
- `FR-12` If some trust data is private or permissioned, the system should still publish verifiable public commitments, for example a periodically updated `merkle tree root` signed by multiple maintainers and anchored in a public contract. Source: Bottom-up Trust Registry.
- `FR-13` The verifier workflow should support trust evaluation based on explicit trust levels or policy criteria, rather than a binary allowlist only. Sources: MIT governance PDF, Bottom-up Trust Registry.
- `FR-14` The system should support negative signals as well as positive ones, such as `negative attestations`, endorsements, or challenge outcomes, because governance sources expect trust and reputation policies to include both. Source: MIT governance PDF.
- `FR-15` Public/private access boundaries must be explicit. Some registry data can be public, but sensitive organizational relationships, competitive information, or disclosure policy internals may need controlled access or private computation. Sources: MIT governance PDF, Dunphy, Bottom-up Trust Registry.

## Governance Requirements

- `GR-1` The registry operator must publish a governance policy that is publicly accessible and referenced from registry metadata via `policy_uri` or equivalent. Source: MIT governance PDF.
- `GR-2` Governance must name the governing parties, their composition, roles, and decision-making rules. This should not be implicit in contract ownership alone. Source: MIT governance PDF.
- `GR-3` Governance must define dispute-resolution procedures for registry decisions, challenges, and membership conflicts. Sources: MIT governance PDF, Dunphy.
- `GR-4` Governance must define transparency and reporting channels for rule changes, participation updates, and operational notices. Source: MIT governance PDF.
- `GR-5` Governance must define issuer onboarding and legitimacy checks, including KYC or equivalent identity proofing and any third-party verification services used. Source: MIT governance PDF.
- `GR-6` Governance must define `periodic reviews` for issuer records, including review criteria and expected processing times. Source: MIT governance PDF.
- `GR-7` Governance must define key-compromise and planned/emergency key-rotation procedures, including audit and notification requirements. Sources: MIT governance PDF, Kanon.
- `GR-8` Governance must define retention, archival, closure, merger, voluntary exit, non-renewal, payment-default, and removal policies for registry participants. Source: MIT governance PDF.
- `GR-9` Governance must define fairness and anti-capture expectations. Dunphy’s design-space analysis makes this explicit: decentralization alone does not ensure fairness, so the system needs governance rules and non-compliance penalties that remain credible over time. Source: Dunphy.
- `GR-10` Governance must define the registry’s adversarial stance: who is trusted to write, who may audit, what failures are tolerated, and whether Byzantine fault tolerance, multisig approval, or challenge windows are required for critical updates. Sources: Dunphy, Bottom-up Trust Registry.
- `GR-11` Governance should minimize storage of private individuals’ data and should explicitly prevent privacy leaks such as issuer “calling home” during verification. Sources: MIT governance PDF, Kanon.
- `GR-12` Governance must specify funding and fee structure because fee volatility or high per-transaction cost is an explicit adoption risk in the Kanon requirements. Sources: Kanon, MIT governance PDF.

## Lifecycle and State-Machine Requirements

- `LR-1` Every registry object should have explicit lifecycle states. Minimum practical states are `proposed`, `authorized`, `active`, `suspended`, `revoked`, `superseded`, and `archived`. This is an inference from the combined sources, not a direct quotation.
- `LR-2` DID documents need historical key state, not only current state. Key rotation therefore needs a state transition that preserves prior keys for later signature verification. Sources: Kanon, MIT governance PDF.
- `LR-3` Schema lifecycle should separate authoring from publication. A schema should not become usable for credential definitions until the governing trust registry authorizes it. Sources: Kanon, Dunphy’s emphasis on actionable state.
- `LR-4` Credential definition lifecycle should require a valid issuer DID, a referenced schema, a linked status method if revocable, and governance approval before issuance begins. Source: Kanon.
- `LR-5` Registry membership records need explicit transitions for authorize, revoke, suspend, reinstate, and expire, all timestamped. Source: Kanon.
- `LR-6` Proposal and voting workflows must be first-class if governance is on-chain. Proposal states should include at least `tabled`, `open`, `closed`, `accepted`, `rejected`, and `executed`. Source: Kanon.
- `LR-7` Critical state used in real-world decisions must have strong finality semantics. Dunphy’s `actionable state` requirement means a verifier cannot depend on a state that may be displaced later by latent updates, especially revocation. Source: Dunphy.
- `LR-8` If private or off-chain trust data is used, it should be committed on a predictable `epoch` schedule so verifiers know which commitment, timestamp, and proof window they are validating against. Source: Bottom-up Trust Registry.
- `LR-9` Revocation or negative trust events should support challenge and evidence workflows, not just unilateral deletion. Bottom-up Trust Registry uses staking and challenge-based penalties; even if the economics differ, the state machine should preserve the notion of contested updates. Source: Bottom-up Trust Registry.
- `LR-10` The system should anticipate transaction hot spots up front, especially revocation and mass onboarding. Dunphy shows that status updates and accumulator operations can dominate latency and should shape the state machine and batching strategy. Source: Dunphy.

## Evidence and Credential Requirements

- `ER-1` The registry must preserve enough evidence to prove who authorized what and when. Minimum evidence includes authorizing DIDs, creator/writer DIDs, signatures, authorization timestamp, revocation timestamp, and the versioned record that was active at decision time. Source: Kanon.
- `ER-2` Verification should be possible without contacting the issuer at presentation time. This is important both for privacy and operational resilience. Sources: Bottom-up Trust Registry, MIT governance PDF.
- `ER-3` Revocation evidence must be non-correlatable. Kanon explicitly rejects designs that create holder-correlating identifiers and calls for a Merkle tree, ZKP, or similar method. Source: Kanon.
- `ER-4` If private trust relationships are used, verifiers should receive a bounded proof package: the relevant path or authorization evidence, inclusion proofs, the anchored root or registry signature, and the epoch/timestamp that binds the proof to a stable view of state. Source: Bottom-up Trust Registry.
- `ER-5` Reader/verifier authorization evidence should include what data can be requested, not only who is authorized. That means allowed attributes, allowed predicates, and disclosure level should be part of the verifiable policy record. Source: Kanon.
- `ER-6` Trust evaluations should be evidentiary, not purely discretionary. MIT’s governance framework explicitly points toward `trust levels or scales` and evidence-based ratings; if those are used, the criteria and resulting level should be inspectable. Source: MIT governance PDF.
- `ER-7` Long-term verification requires `retention and archival` of issuer metadata, key history, and governance state. Otherwise an old credential may become unverifiable after issuer exit, merger, or key rollover. Source: MIT governance PDF.
- `ER-8` Where live revocation is operationally expensive, short-lived credentials are a viable design mitigation. This is an architectural inference grounded in Dunphy’s finding that revocation freshness and throughput limits can undermine non-repudiation. Source: Dunphy.

## Highest-Priority Design Decisions For Smart Contracts

- Separate governance authorization from revocation/status updates.
- Represent historical state explicitly; do not overwrite it away.
- Make verifier-consumable policy records first-class: trust level, disclosure permissions, governance policy link, and status method.
- Choose finality and update cadence based on dispute resolution and revocation freshness, not on generic blockchain preference.
- Treat privacy as a protocol requirement, not a UI concern: no holder correlation, no calling home, minimal disclosure by default.
