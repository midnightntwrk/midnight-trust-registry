import { Buffer } from "node:buffer";
import { describe, expect, it, vi } from "vitest";

import {
  decodeJubjubSignature,
  encodeJubjubSignature,
  JUBJUB_ORDER,
  signApplicationEvidenceCommitmentFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  AuthorizationStatus as ContractAuthorizationStatus,
  IssuerResourceType,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import {
  computeApplicationEvidenceCommitment,
  computeGovernancePolicySnapshotCommitment,
  computeIssuerStatusPolicyBindingCommitment,
  deriveGovernancePolicySnapshot,
  requestGovernedResourceId,
  resolveGovernancePolicyTemplate,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  bytes32Commitment,
  createIssuerAuthorizationScopeFixture,
  createVerifierAuthorizationScopeFixture,
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("trust registry local simulator integration", () => {
  it("proposes every supported issuer resource against its canonical scope", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    for (const resourceType of [
      IssuerResourceType.credentialFamily,
      IssuerResourceType.schema,
      IssuerResourceType.schemaVersion,
      IssuerResourceType.credentialDefinition,
      IssuerResourceType.statusMethodRequirement,
    ]) {
      const issuer = createIssuerScenarioFixture(`resource-${resourceType}`, resourceType);
      expect(() => harness.proposeIssuer(issuer)).not.toThrow();
      const scope = createIssuerAuthorizationScopeFixture(issuer);
      const governedResource = {
        type: (["credentialFamily", "schema", "schemaVersion", "credentialDefinition", "statusMethodRequirement"] as const)[resourceType]!,
        id: issuer.resourceId,
      };
      expect(() => harness.createApplicationEvidence({
        applicationId: issuer.authorizationId,
        subjectDid: issuer.subjectDid,
        role: "issuer",
        scope,
        governedResource: { ...governedResource, id: "unapproved-resource" },
      })).toThrow(/outside the scope/);
      const validEvidence = harness.createApplicationEvidence({
        applicationId: issuer.authorizationId,
        subjectDid: issuer.subjectDid,
        role: "issuer",
        scope,
        governedResource,
      });
      expect(() => harness.assertApplicationEvidence({
        evidence: validEvidence,
        applicationId: issuer.authorizationId,
        subjectDid: issuer.subjectDid,
        role: "issuer",
        scope,
        governedResource: { ...governedResource, id: "unapproved-resource" },
      })).toThrow(/outside the scope/);
      expect(() => harness.createApplicationEvidence({
        applicationId: issuer.authorizationId,
        subjectDid: issuer.subjectDid,
        role: "issuer",
        scope,
      })).toThrow(/explicit governed resource/);
      expect(() => harness.proposeIssuerWithApplicationEvidence(
        issuer,
        harness.createApplicationEvidence({
          applicationId: issuer.authorizationId,
          subjectDid: issuer.subjectDid,
          role: "issuer",
          scope,
          governedResource,
        }),
        [],
        {
          scope: { ...scope, statusMethod: "substituted-method" },
          challengeHash: sha256Hex("unused"),
          governedResource,
        },
      )).toThrow(/proposal scope does not match/);
    }
  });

  it.each([
    [IssuerResourceType.schemaVersion, "schemaVersion"],
    [IssuerResourceType.statusMethodRequirement, "statusMethodRequirement"],
  ] as const)("keeps two %s issuer resources with the same bare value distinct", (resourceType, resourceKind) => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const first = createIssuerScenarioFixture(`composite-first-${resourceKind}`, resourceType);
    const secondFixture = createIssuerScenarioFixture(`composite-second-${resourceKind}`, resourceType);
    const second = {
      ...secondFixture,
      subjectDid: first.subjectDid,
      subjectDidCommitment: first.subjectDidCommitment,
      statusAuthorityVerificationMethod: `${first.subjectDid}#status-1`,
    };
    expect(first.authorizationScope.schemaVersion).toBe(second.authorizationScope.schemaVersion);
    expect(first.authorizationScope.statusMethod).toBe(second.authorizationScope.statusMethod);
    expect(first.resourceId).not.toBe(second.resourceId);

    expect(() => harness.createApplicationEvidence({
      applicationId: second.authorizationId,
      subjectDid: second.subjectDid,
      role: "issuer",
      scope: second.authorizationScope,
      governedResource: { type: resourceKind, id: first.resourceId },
    })).toThrow(/outside the scope/);

    harness.authorizeIssuer(first);
    harness.authorizeIssuer(second);
    for (const fixture of [first, second]) {
      const current = harness.simulator.getCurrentIssuerAuthorization(
        fixture.subjectDidCommitment,
        fixture.resourceType,
        fixture.resourceIdCommitment,
      );
      expect(Buffer.from(current.authorizationId)).toEqual(Buffer.from(fixture.authorizationIdCommitment));
      const historical = harness.buildIssuerHistoricalEvidence(fixture);
      expect(historical.authorization?.resourceId).toBe(fixture.resourceId);
      const active = harness.evaluateCurrentIssuerDecision(fixture);
      expect(active.authorization?.authorizationId).toBe(fixture.authorizationId);
    }
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    expect(() => client.verifyIssuerAuthorizationBundle(harness.buildIssuerHistoricalEvidence(second), {
      expectedResourceId: first.resourceId,
    })).toThrow(/resource mismatch/i);
    expect(() => harness.simulator.assertIssuerAuthorized(
      first.subjectDidCommitment,
      resourceType,
      bytes32Commitment(resourceKind === "schemaVersion" ? "1.0.0" : "midnight-status-registry-v1"),
    )).toThrow();
  });

  it("preserves issuer application history before activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("application");

    harness.proposeIssuer(issuer);

    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const proposedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(proposedBundle.authorization?.status).toBe("proposed");
    expect(proposedBundle.authorization?.authorizedAt).toBeUndefined();
    expect(proposedBundle.authorization?.activeFrom).toBeUndefined();

    harness.approveIssuer(issuer);

    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const authorizedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(authorizedBundle.authorization?.status).toBe("authorized");
    expect(authorizedBundle.authorization?.authorizedAt).toBeDefined();
    expect(authorizedBundle.authorization?.activeFrom).toBeUndefined();

    harness.activateIssuer(issuer);

    const activeBundle = harness.evaluateCurrentIssuerDecision(issuer, {
      expectedRegistryId: harness.registryId,
    });
    expect(activeBundle.authorization?.status).toBe("active");
    expect(activeBundle.authorization?.activeFrom).toBeDefined();
  });

  it.each([
    [1, "approval", ContractAuthorizationStatus.proposed],
    [2, "activation", ContractAuthorizationStatus.authorized],
  ] as const)("rejects evidence expired before issuer %s", (minutes, transition, status) => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture(`expires-before-${transition}`);
    const original = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: "credentialFamily", id: issuer.resourceId },
    });
    const envelope = {
      ...original.envelope,
      expiresAt: new Date(Date.parse(original.envelope.verifiedAt) + minutes * 60_000).toISOString(),
    };
    const commitment = computeApplicationEvidenceCommitment(envelope);
    harness.proposeIssuerWithApplicationEvidence(issuer, {
      envelope,
      commitment,
      signature: harness.signApplicationEvidenceCommitment(commitment),
    });
    if (transition === "activation") harness.approveIssuer(issuer);
    harness.advanceEvidenceTimeBy(minutes * 60_000);

    expect(() => transition === "approval"
      ? harness.approveIssuer(issuer)
      : harness.activateIssuer(issuer)).toThrow(/expiresAt|expired/);
    expect(harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment).status).toBe(status);
  });

  it("expires an idle issuer proposal without advancing the governance sequence", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("idle-expiry");
    harness.proposeIssuer(issuer);
    const sequence = harness.simulator.getLedger().governanceActionCount;

    harness.advanceEvidenceTimeBy(24 * 60 * 60 * 1000);

    expect(harness.simulator.getLedger().governanceActionCount).toBe(sequence);
    expect(() => harness.approveIssuer(issuer)).toThrow(/expiresAt|expired/);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(sequence);
    expect(harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment).status)
      .toBe(ContractAuthorizationStatus.proposed);
  });

  it("rejects malformed application evidence before an issuer proposal reaches Compact", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("application-evidence-negative");
    const validEvidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: "credentialFamily", id: issuer.resourceId },
    });
    const decodedSignature = decodeJubjubSignature(
      Buffer.from(validEvidence.signature.value.slice(2), "hex"),
    );

    const cases: ReadonlyArray<
      readonly [
        string,
        {
          envelope?: Partial<typeof validEvidence.envelope>;
          signature?: Partial<typeof validEvidence.signature>;
        },
        RegExp,
      ]
    > = [
      ["wrong application", { envelope: { applicationId: "application:issuer:other:v1" } }, /applicationId/],
      ["wrong subject", { envelope: { subjectDid: "did:midnight:issuer:other" } }, /subjectDid/],
      ["wrong role", { envelope: { role: "verifier" as const } }, /role/],
      ["wrong policy", { envelope: { policyId: "policy:wrong:v1" } }, /policyId/],
      ["wrong challenge", { envelope: { challengeHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } }, /challengeHash/],
      [
        "wrong scope",
        { envelope: { scopeCommitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
        /scopeCommitment|Issuer resource id does not match/,
      ],
      ["unauthorized verifier", { envelope: { evidenceVerifierDid: "did:midnight:evidence-verifier:other" } }, /not authorized/],
      ["expired evidence", { envelope: { expiresAt: "2026-05-20T00:00:00Z" } }, /expiresAt/],
      ["future evidence", { envelope: { verifiedAt: "2026-05-20T01:00:00Z" } }, /not yet valid/],
      ["invalid signature", { signature: { value: "tampered" } }, /signature is invalid/],
      ["truncated signature", { signature: { value: validEvidence.signature.value.slice(0, -1) } }, /signature is invalid/],
      ["non-hex signature", { signature: { value: `${validEvidence.signature.value.slice(0, -1)}g` } }, /signature is invalid/],
      ["noncanonical signature encoding", { signature: { value: validEvidence.signature.value.toUpperCase() } }, /signature is invalid/],
      ["invalid curve point", { signature: { value: `0x${"00".repeat(96)}` } }, /signature is invalid/],
      [
        "malleated response scalar",
        {
          signature: {
            value: `0x${Buffer.from(encodeJubjubSignature({
              ...decodedSignature,
              response: decodedSignature.response + JUBJUB_ORDER,
            })).toString("hex")}`,
          },
        },
        /signature is invalid/,
      ],
      ["unauthorized key id", { signature: { keyId: `${harness.evidenceVerifier.did}#assertion-2` } }, /key is not authorized/],
      [
        "wrong signer key",
        {
          signature: {
            value: `0x${Buffer.from(encodeJubjubSignature(
              signApplicationEvidenceCommitmentFromSeed(
                new Uint8Array(32).fill(99),
                bytes32Commitment(validEvidence.signature.keyId),
                Buffer.from(validEvidence.commitment.slice(2), "hex"),
              ),
            )).toString("hex")}`,
          },
        },
        /signature is invalid/,
      ],
    ] as const;

    for (const [_name, mutation, expectedError] of cases) {
      const evidence = {
        ...validEvidence,
        envelope: { ...validEvidence.envelope, ...mutation.envelope },
        signature: { ...validEvidence.signature, ...mutation.signature },
      };
      expect(() => {
        if (_name !== "expired evidence") {
          evidence.commitment = computeApplicationEvidenceCommitment(evidence.envelope);
        }
        harness.proposeIssuerWithApplicationEvidence(issuer, evidence);
      }).toThrow(expectedError);
    }
  });

  it("binds validated application evidence for issuer, verifier, auditor, and maintainer proposals", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("application-evidence-issuer");
    const verifier = createVerifierScenarioFixture("application-evidence-verifier");
    const auditor = createAuditorScenarioFixture("application-evidence-auditor");
    const maintainer = createMaintainerScenarioFixture("application-evidence-maintainer");

    const issuerEvidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: "credentialFamily", id: issuer.resourceId },
    });
    harness.proposeIssuerWithApplicationEvidence(issuer, issuerEvidence);
    harness.proposeVerifier(verifier);
    harness.proposeAuditor(auditor);
    harness.proposeMaintainer(maintainer);

    expect(
      Array.from(harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment).evidenceHash),
    ).toEqual(Array.from(Buffer.from(issuerEvidence.commitment.slice(2), "hex")));
    expect(harness.simulator.getVerifierAuthorization(verifier.authorizationIdCommitment).status).toBe(
      ContractAuthorizationStatus.proposed,
    );
    expect(harness.simulator.getAuditorAuthorization(auditor.authorizationIdCommitment).status).toBe(
      ContractAuthorizationStatus.proposed,
    );
    expect(harness.simulator.getMaintainerMembership(maintainer.maintainerIdCommitment).status).toBe(
      ContractAuthorizationStatus.proposed,
    );
  });

  it("authorizes an issuer and emits a valid active evidence bundle", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");

    harness.authorizeIssuer(issuer);

    const bundle = harness.evaluateCurrentIssuerDecision(issuer, {
      expectedRegistryId: harness.registryId,
    });

    expect(bundle.authorization?.role).toBe("issuer");
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.resourceId).toBe(issuer.resourceId);
    expect(bundle.subjectDid).toBe(issuer.subjectDid);
    expect(bundle.registryId).toBe(harness.registryId);
    expect(bundle.statusPolicyBinding?.statusRegistryId).toBe(issuer.statusRegistryId);
    expect(bundle.authorization?.statusPolicyBindingCommitment).toBe(
      computeIssuerStatusPolicyBindingCommitment(bundle.statusPolicyBinding!),
    );
    expect(bundle.referencedStatusRegistryId).toBeUndefined();
    expect(bundle.epoch.maintainerSignatures).toHaveLength(1);
  });

  it("rejects current issuer trust after suspension and revocation but preserves historical evidence through archival", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("passport");

    harness.authorizeIssuer(issuer);
    harness.suspendIssuer(issuer);

    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const suspendedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(suspendedBundle.authorization?.status).toBe("suspended");
    const anchoredStatusPolicy = suspendedBundle.authorization?.statusPolicyBindingCommitment;
    expect(anchoredStatusPolicy).toBe(
      computeIssuerStatusPolicyBindingCommitment(suspendedBundle.statusPolicyBinding!),
    );

    harness.revokeIssuer(issuer);
    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const revokedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(revokedBundle.authorization?.status).toBe("revoked");
    expect(revokedBundle.authorization?.statusPolicyBindingCommitment).toBe(anchoredStatusPolicy);

    harness.archiveIssuer(issuer);
    const archivedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(archivedBundle.authorization?.status).toBe("archived");
    expect(archivedBundle.authorization?.statusPolicyBindingCommitment).toBe(anchoredStatusPolicy);
    expect(archivedBundle.authorization?.archivedAt).toBeDefined();
  });

  it("enforces scoped maintainer quorum rules for issuer onboarding, emergency action, and archival action", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const secondMaintainer = createMaintainerScenarioFixture("quorum-second");
    const issuer = createIssuerScenarioFixture("quorum-onboarding");

    harness.authorizeMaintainer(secondMaintainer);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    expect(resolveGovernancePolicyTemplate(harness.policyRecord, "member")).toMatchObject({
      requiredMaintainerThreshold: 2,
    });
    expect(
      resolveGovernancePolicyTemplate(harness.policyRecord, "emergency"),
    ).toMatchObject({
      requiredMaintainerThreshold: 1,
    });
    expect(resolveGovernancePolicyTemplate(harness.policyRecord, "archival")).toMatchObject({
      requiredMaintainerThreshold: 2,
    });

    expect(() => harness.proposeIssuer(issuer)).toThrow(/action threshold/i);

    harness.proposeIssuer(issuer, [secondMaintainer]);
    harness.approveIssuer(issuer, [secondMaintainer]);
    harness.activateIssuer(issuer, [secondMaintainer]);

    const activeBundle = harness.evaluateCurrentIssuerDecision(issuer, {
      expectedRegistryId: harness.registryId,
    });
    expect(activeBundle.authorization?.status).toBe("active");

    harness.suspendIssuer(issuer);

    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const suspendedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(suspendedBundle.authorization?.status).toBe("suspended");

    expect(() => harness.archiveIssuer(issuer)).toThrow(/action threshold/i);

    harness.archiveIssuer(issuer, [secondMaintainer]);

    const archivedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(archivedBundle.authorization?.status).toBe("archived");
  });

  it("keeps historical evidence on the original policy after a signed threshold revision", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const beforeRevision = createIssuerScenarioFixture("before-policy-revision");
    const latePublished = createIssuerScenarioFixture("late-published-policy-revision");
    const afterRevision = createIssuerScenarioFixture("after-policy-revision");
    const secondMaintainer = createMaintainerScenarioFixture("revision-second");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    harness.authorizeIssuer(beforeRevision);
    const originalBundle = harness.evaluateCurrentIssuerDecision(beforeRevision);
    harness.authorizeIssuer(latePublished);
    harness.authorizeMaintainer(secondMaintainer);
    const revisionSequence = harness.simulator.getLedger().governanceActionCount;
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    expect(harness.simulator.getLedger().governancePolicyEffectiveFromByVersion.lookup(2n))
      .toBe(revisionSequence + 1n);

    harness.proposeIssuer(afterRevision, [secondMaintainer]);
    harness.approveIssuer(afterRevision, [secondMaintainer]);
    harness.activateIssuer(afterRevision, [secondMaintainer]);
    const currentBundle = harness.evaluateCurrentIssuerDecision(afterRevision);
    const historicalBundle = harness.buildIssuerHistoricalEvidence(beforeRevision);
    const latePublishedBundle = harness.buildIssuerHistoricalEvidence(latePublished);

    expect(historicalBundle.policy.version).toBe("v1");
    expect(currentBundle.policy.version).toBe("v2");
    expect(Date.parse(currentBundle.policy.effectiveFrom) - Date.parse(harness.registryRecord.updatedAt))
      .toBe(60_000);
    expect(harness.registryRecord.policyUri).toBe(currentBundle.policy.policyUri);
    expect(historicalBundle.epoch.policyRoot).toBe(originalBundle.epoch.policyRoot);
    expect(latePublishedBundle.epoch.policyRoot).toBe(originalBundle.epoch.policyRoot);
    expect(currentBundle.epoch.policyRoot).not.toBe(originalBundle.epoch.policyRoot);
    const latePublishedRecord = client.getEpochCommitmentById(
      latePublishedBundle.epoch.epochId,
    );
    expect(`0x${Buffer.from(latePublishedRecord.publicationPolicyCommitment).toString("hex")}`)
      .toBe(currentBundle.epoch.policyRoot);
    expect(latePublishedBundle.epoch.policyRoot).not.toBe(
      `0x${Buffer.from(latePublishedRecord.publicationPolicyCommitment).toString("hex")}`,
    );
    expect(currentBundle.epoch.policyRoot).toBe(
      computeGovernancePolicySnapshotCommitment(
        deriveGovernancePolicySnapshot(currentBundle.policy),
      ),
    );
    expect(harness.simulator.getLedger().governancePolicyVersion).toBe(2n);
    expect(() => client.verifyIssuerAuthorizationBundle(historicalBundle, {})).not.toThrow();
    expect(() => client.verifyIssuerAuthorizationBundle(latePublishedBundle, {})).not.toThrow();
    expect(() => client.verifyIssuerAuthorizationBundle(currentBundle, {})).not.toThrow();
    expect(() => client.verifyIssuerAuthorizationBundle(historicalBundle, {
      evaluationTime: currentBundle.policy.effectiveFrom,
    })).toThrow(/policy snapshot is superseded/i);
    expect(() => harness.assertPublishedEpochEvidence(historicalBundle, {
      evaluationTime: currentBundle.policy.effectiveFrom,
    })).toThrow(/policy snapshot is superseded/i);
    expect(() => client.verifyIssuerAuthorizationBundle(
      { ...historicalBundle, policy: { ...historicalBundle.policy, version: "v9" } },
      {},
    )).toThrow(/not committed to the ledger/i);
    expect(() => client.verifyIssuerAuthorizationBundle(historicalBundle, {
      evaluationTime: "not-a-date",
    })).toThrow(/evaluation time is invalid/i);
    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...historicalBundle,
          policy: { ...historicalBundle.policy, version: "v2" },
        },
        {},
      ),
    ).toThrow(/committed ledger version/i);
    harness.assertPublishedEpochEvidence(historicalBundle);
    harness.assertPublishedEpochEvidence(latePublishedBundle);
    harness.assertPublishedEpochEvidence(currentBundle);
  });

  it("authorizes a verifier for a composite request scope and emits a valid active evidence bundle", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("age-gate");

    harness.authorizeVerifier(verifier);

    const bundle = harness.evaluateCurrentVerifierDecision(verifier, {
      expectedRegistryId: harness.registryId,
    });

    expect(bundle.authorization?.role).toBe("verifier");
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.resourceType).toBe("request-profile");
    expect(bundle.authorization?.resourceId).toBe(verifier.scopeResourceId);
    expect(bundle.subjectDid).toBe(verifier.subjectDid);
  });

  it("keeps same-profile verifier purposes distinct in current and historical evidence", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const first = createVerifierScenarioFixture("same-profile-purpose");
    const otherPurpose = "research";
    const otherResourceId = requestGovernedResourceId({
      ...createVerifierAuthorizationScopeFixture(first),
      purpose: otherPurpose,
    });
    const authorizationId = "auth:verifier:same-profile-purpose:research:v1";
    const second = {
      ...first,
      authorizationId,
      authorizationIdCommitment: bytes32Commitment(authorizationId),
      purpose: otherPurpose,
      scopeResourceId: otherResourceId,
      requestResourceIdCommitment: bytes32Commitment(otherResourceId),
    };
    harness.authorizeVerifier(first);
    harness.authorizeVerifier(second);
    expect(Buffer.from(harness.simulator.getVerifierAuthorization(second.authorizationIdCommitment).requestResourceId))
      .toEqual(Buffer.from(bytes32Commitment(otherResourceId)));
    expect(harness.evaluateCurrentVerifierDecision(first).authorization?.resourceId).toBe(first.scopeResourceId);
    expect(harness.evaluateCurrentVerifierDecision(second).authorization?.resourceId).toBe(otherResourceId);
    expect(harness.buildVerifierHistoricalEvidence(first).authorization?.authorizationId).toBe(first.authorizationId);
    expect(harness.buildVerifierHistoricalEvidence(second).authorization?.authorizationId).toBe(authorizationId);
  });

  it("preserves verifier application history before activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("employment-application");

    harness.proposeVerifier(verifier);

    expect(() => harness.evaluateCurrentVerifierDecision(verifier)).toThrow(/not active/i);
    const proposedBundle = harness.buildVerifierHistoricalEvidence(verifier);
    expect(proposedBundle.authorization?.status).toBe("proposed");
    expect(proposedBundle.authorization?.authorizedAt).toBeUndefined();
    expect(proposedBundle.authorization?.activeFrom).toBeUndefined();

    harness.approveVerifier(verifier);

    expect(() => harness.evaluateCurrentVerifierDecision(verifier)).toThrow(/not active/i);
    const authorizedBundle = harness.buildVerifierHistoricalEvidence(verifier);
    expect(authorizedBundle.authorization?.status).toBe("authorized");
    expect(authorizedBundle.authorization?.authorizedAt).toBeDefined();
    expect(authorizedBundle.authorization?.activeFrom).toBeUndefined();

    harness.activateVerifier(verifier);

    const activeBundle = harness.evaluateCurrentVerifierDecision(verifier, {
      expectedRegistryId: harness.registryId,
    });
    expect(activeBundle.authorization?.status).toBe("active");
    expect(activeBundle.authorization?.activeFrom).toBeDefined();
  });

  it("rejects verifier trust for wrong registry, mismatched scope, and revoked lifecycle state", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("employment");

    harness.authorizeVerifier(verifier);

    expect(() =>
      harness.evaluateCurrentVerifierDecision(verifier, {
        expectedRegistryId: "registry:other:trusted",
      }),
    ).toThrow(/registry mismatch/i);

    const mismatchedScope = {
      ...verifier,
      allowedPredicateSetCommitment: verifier.allowedAttributeSetCommitment,
    };
    expect(() => harness.evaluateCurrentVerifierDecision(mismatchedScope)).toThrow(
      /scope is not registered/i,
    );

    harness.revokeVerifier(verifier);
    expect(() => harness.evaluateCurrentVerifierDecision(verifier)).toThrow(
      /not active/i,
    );
    const revokedBundle = harness.buildVerifierHistoricalEvidence(verifier);
    expect(revokedBundle.authorization?.status).toBe("revoked");
  });

  it("authorizes an external recognition and emits a valid active evidence bundle", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("gaia-x");

    harness.authorizeRecognition(recognition);

    const bundle = harness.evaluateCurrentRecognitionDecision(recognition, {
      expectedRegistryId: harness.registryId,
    });

    expect(bundle.recognition?.status).toBe("active");
    expect(bundle.recognition?.recognizedAuthorityDid).toBe(
      recognition.recognizedAuthorityDid,
    );
    expect(bundle.recognition?.recognizedRegistryId).toBe(
      recognition.recognizedRegistryId,
    );
    expect(bundle.recognition?.scope.resourceType).toBe(
      recognition.scopeResourceType,
    );
    expect(bundle.recognition?.scope.resourceId).toBe(recognition.scopeResourceId);
    expect(bundle.subjectDid).toBe(recognition.recognizedAuthorityDid);
    expect(bundle.authorization).toBeUndefined();
  });

  it("preserves recognition application history before activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("gaia-x-application");

    harness.proposeRecognition(recognition);

    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const proposedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(proposedBundle.recognition?.status).toBe("proposed");
    expect(proposedBundle.recognition?.authorizedAt).toBeUndefined();
    expect(proposedBundle.recognition?.effectiveFrom).toBeUndefined();

    harness.approveRecognition(recognition);

    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const authorizedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(authorizedBundle.recognition?.status).toBe("authorized");
    expect(authorizedBundle.recognition?.authorizedAt).toBeDefined();
    expect(authorizedBundle.recognition?.effectiveFrom).toBeUndefined();

    harness.activateRecognition(recognition);

    const activeBundle = harness.evaluateCurrentRecognitionDecision(recognition, {
      expectedRegistryId: harness.registryId,
    });
    expect(activeBundle.recognition?.status).toBe("active");
    expect(activeBundle.recognition?.effectiveFrom).toBeDefined();
  });

  it("rejects current recognition after suspension and revocation but preserves historical evidence through archival", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("eidas");

    harness.authorizeRecognition(recognition);
    harness.suspendRecognition(recognition);

    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const suspendedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(suspendedBundle.recognition?.status).toBe("suspended");

    harness.revokeRecognition(recognition);
    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const revokedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(revokedBundle.recognition?.status).toBe("revoked");

    harness.archiveRecognition(recognition);
    const archivedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(archivedBundle.recognition?.status).toBe("archived");
    expect(archivedBundle.recognition?.archivedAt).toBeDefined();
  });

  it("rejects recognition trust for wrong registry, mismatched scope, and revoked lifecycle state", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("ebsi");

    harness.authorizeRecognition(recognition);

    expect(() =>
      harness.evaluateCurrentRecognitionDecision(recognition, {
        expectedRegistryId: "registry:other:trusted",
      }),
    ).toThrow(/registry mismatch/i);

    const mismatchedScope = {
      ...recognition,
      scopeResourceIdCommitment: recognition.scopeResourceTypeCommitment,
    };
    expect(() => harness.evaluateCurrentRecognitionDecision(mismatchedScope)).toThrow(
      /scope is not registered/i,
    );

    harness.revokeRecognition(recognition);
    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const revokedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(revokedBundle.recognition?.status).toBe("revoked");
  });

  it("authorizes a trusted auditor and emits a valid active evidence bundle", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const auditor = createAuditorScenarioFixture("iso-27001");

    harness.authorizeAuditor(auditor);

    const bundle = harness.evaluateCurrentAuditorDecision(auditor, {
      expectedRegistryId: harness.registryId,
    });

    expect(bundle.authorization?.role).toBe("auditor");
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.resourceType).toBe("request-profile");
    expect(bundle.authorization?.resourceId).toBe(auditor.scopeResourceId);
    expect(bundle.subjectDid).toBe(auditor.subjectDid);
  });

  it("keeps same-profile auditor credential scopes distinct in current and historical evidence", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const first = createAuditorScenarioFixture("same-profile-credential-scope");
    const credentialScopeCommitment = sha256Hex("audit:other-credential-scope");
    const otherResourceId = requestGovernedResourceId({
      ...createAuditorAuthorizationScopeFixture(first),
      credentialScopeCommitment,
    });
    const authorizationId = "auth:auditor:same-profile-credential-scope:other:v1";
    const second = {
      ...first,
      authorizationId,
      authorizationIdCommitment: bytes32Commitment(authorizationId),
      credentialScopeCommitment,
      scopeResourceId: otherResourceId,
      requestResourceIdCommitment: bytes32Commitment(otherResourceId),
    };
    harness.authorizeAuditor(first);
    harness.authorizeAuditor(second);
    expect(Buffer.from(harness.simulator.getAuditorAuthorization(second.authorizationIdCommitment).requestResourceId))
      .toEqual(Buffer.from(bytes32Commitment(otherResourceId)));
    expect(harness.evaluateCurrentAuditorDecision(first).authorization?.resourceId).toBe(first.scopeResourceId);
    expect(harness.evaluateCurrentAuditorDecision(second).authorization?.resourceId).toBe(otherResourceId);
    expect(harness.buildAuditorHistoricalEvidence(first).authorization?.authorizationId).toBe(first.authorizationId);
    expect(harness.buildAuditorHistoricalEvidence(second).authorization?.authorizationId).toBe(authorizationId);
  });

  it("rejects current auditor trust after suspension and revocation but preserves historical evidence through archival", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const auditor = createAuditorScenarioFixture("gdpr");

    harness.authorizeAuditor(auditor);
    harness.suspendAuditor(auditor);

    expect(() => harness.evaluateCurrentAuditorDecision(auditor)).toThrow(/not active/i);
    const suspendedBundle = harness.buildAuditorHistoricalEvidence(auditor);
    expect(suspendedBundle.authorization?.status).toBe("suspended");

    harness.revokeAuditor(auditor);
    expect(() => harness.evaluateCurrentAuditorDecision(auditor)).toThrow(/not active/i);
    const revokedBundle = harness.buildAuditorHistoricalEvidence(auditor);
    expect(revokedBundle.authorization?.status).toBe("revoked");

    harness.archiveAuditor(auditor);
    const archivedBundle = harness.buildAuditorHistoricalEvidence(auditor);
    expect(archivedBundle.authorization?.status).toBe("archived");
    expect(archivedBundle.authorization?.archivedAt).toBeDefined();
  });

  it("governs maintainer membership through proposal, approval, activation, and lifecycle state changes", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const candidate = createMaintainerScenarioFixture("governed");

    harness.proposeMaintainer(candidate);
    expect(
      harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status,
    ).toBe(ContractAuthorizationStatus.proposed);

    harness.approveMaintainer(candidate);
    expect(
      harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status,
    ).toBe(ContractAuthorizationStatus.authorized);

    harness.activateMaintainer(candidate);
    const activeMembership = harness.simulator.getCurrentMaintainerMembership(
      candidate.subjectDidCommitment,
    );
    expect(activeMembership.status).toBe(ContractAuthorizationStatus.active);
    expect(harness.simulator.getLedger().activeMaintainerCount).toBe(2n);

    harness.suspendMaintainer(candidate);
    expect(
      harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status,
    ).toBe(ContractAuthorizationStatus.suspended);
    expect(harness.simulator.getLedger().activeMaintainerCount).toBe(1n);

    harness.revokeMaintainer(candidate);
    expect(
      harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status,
    ).toBe(ContractAuthorizationStatus.revoked);

    harness.archiveMaintainer(candidate);
    expect(
      harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status,
    ).toBe(ContractAuthorizationStatus.archived);
  });

  it("rejects duplicate live maintainer identity enrollment and refuses to deactivate the last active maintainer", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const candidate = createMaintainerScenarioFixture("self");
    candidate.subjectDidCommitment = harness.maintainerDidCommitment;

    expect(() => harness.proposeMaintainer(candidate)).toThrow(
      /already has a live membership/i,
    );

    const bootstrapMembership = {
      maintainerIdCommitment: harness.maintainerIdCommitment,
      maintainerId: harness.maintainerId,
      subjectDidCommitment: harness.maintainerDidCommitment,
      keyId: harness.simulator.getLedger().lastAuthorizedMaintainerKeyId,
      seed: new Uint8Array(32),
      subjectDid: harness.maintainerDid,
      trustLevel: "bootstrap-maintainer",
    };

    expect(() => harness.suspendMaintainer(bootstrapMembership)).toThrow(
      /threshold policy/i,
    );
  });

  it("rejects evidence from an incompatible contract format at both verification boundaries", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("format-boundary");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    harness.publishRegistryEpoch();
    const applicationInput = {
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer" as const,
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: "credentialFamily" as const, id: issuer.resourceId },
    };
    const applicationEvidence = harness.createApplicationEvidence(applicationInput);
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const ledger = harness.simulator.getLedger();
    const spy = vi.spyOn(harness.simulator, "getLedger").mockReturnValue({
      ...ledger,
      contractVersion: 2n,
    });
    const epochRead = vi.spyOn(client, "getEpochCommitmentById").mockImplementation(() => {
      throw new Error("Epoch read should not precede the format gate");
    });
    const simulatorEpochRead = vi.spyOn(harness.simulator, "getEpochCommitment").mockImplementation(() => {
      throw new Error("Simulator epoch read should not precede the format gate");
    });
    const issuerRecordRead = vi.spyOn(harness.simulator, "getIssuerAuthorization").mockImplementation(() => {
      throw new Error("Issuer record read should not precede the format gate");
    });
    try {
      expect(() => harness.publishRegistryEpoch()).toThrow(/Unsupported trust registry format/);
      expect(() => harness.createApplicationEvidence(applicationInput)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.assertApplicationEvidence({
        ...applicationInput,
        evidence: applicationEvidence,
      })).toThrow(/Unsupported trust registry format/);
      expect(() => harness.assertPublishedEpochEvidence(bundle)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.readIssuerAuthorizationStatus(issuer)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.buildIssuerHistoricalEvidence(issuer)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/Unsupported trust registry format/);
      const verifier = createVerifierScenarioFixture("format-boundary");
      expect(() => harness.readVerifierAuthorizationStatus(verifier)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.buildVerifierHistoricalEvidence(verifier)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.evaluateCurrentVerifierDecision(verifier)).toThrow(/Unsupported trust registry format/);
      const auditor = createAuditorScenarioFixture("format-boundary");
      expect(() => harness.buildAuditorHistoricalEvidence(auditor)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.evaluateCurrentAuditorDecision(auditor)).toThrow(/Unsupported trust registry format/);
      const recognition = createRecognitionScenarioFixture("format-boundary");
      expect(() => harness.readRecognitionStatus(recognition)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.buildRecognitionHistoricalEvidence(recognition)).toThrow(/Unsupported trust registry format/);
      expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(/Unsupported trust registry format/);
      expect(() => client.verifyIssuerAuthorizationBundle(bundle, {})).toThrow(/Unsupported trust registry format/);
      expect(epochRead).not.toHaveBeenCalled();
      expect(simulatorEpochRead).not.toHaveBeenCalled();
      expect(issuerRecordRead).not.toHaveBeenCalled();
      expect(() => new TrustRegistrySimulatorClient(harness.simulator)).toThrow(/Unsupported trust registry format/);
    } finally {
      issuerRecordRead.mockRestore();
      simulatorEpochRead.mockRestore();
      epochRead.mockRestore();
      spy.mockRestore();
    }
    expect(() => harness.assertPublishedEpochEvidence({
      ...bundle,
      policy: { ...bundle.policy, version: "vx" },
    })).toThrow("Policy version is invalid");
  });

  it("rejects anchored evidence with a wrong root, a stale epoch window, or a tampered maintainer signature", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("university");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    const originalSignature = bundle.epoch.maintainerSignatures[0];
    if (originalSignature === undefined) {
      throw new Error("expected an epoch maintainer signature");
    }
    const tamperedSignature = `0x${
      originalSignature.signature.slice(2, 3) === "0" ? "1" : "0"
    }${originalSignature.signature.slice(3)}`;

    expect(() =>
      harness.assertPublishedEpochEvidence({
        ...bundle,
        epoch: {
          ...bundle.epoch,
          stateRoot: bundle.epoch.eventRoot,
        },
      }),
    ).toThrow(/state root mismatch/i);

    expect(() =>
      harness.assertPublishedEpochEvidence(bundle, {
        evaluationTime: new Date(
          Date.parse(bundle.epoch.validUntil) + 60_000,
        ).toISOString(),
      }),
    ).toThrow(/stale/i);

    expect(() => harness.assertPublishedEpochEvidence({
      ...bundle,
      epoch: {
        ...bundle.epoch,
        maintainerSignatures: [originalSignature, {
          ...originalSignature,
          keyId: "did:midnight:untrusted#key-2",
          signature: `0x${"00".repeat(96)}`,
        }] as unknown as typeof bundle.epoch.maintainerSignatures,
      },
    })).toThrow("Epoch commitment must include exactly one maintainer signature");

    expect(() => harness.assertPublishedEpochEvidence({
      ...bundle,
      epoch: {
        ...bundle.epoch,
        maintainerSignatures: [] as unknown as typeof bundle.epoch.maintainerSignatures,
      },
    })).toThrow("Epoch commitment must include exactly one maintainer signature");

    const epochRecord = harness.simulator.getEpochCommitment(
      bytes32Commitment(bundle.epoch.epochId),
    );
    for (const malformed of [
      undefined,
      "not-bytes",
      new Uint8Array(31),
      new Uint8Array(33),
      new Uint8Array(32),
    ]) {
      const malformedLedger = vi.spyOn(harness.simulator, "getEpochCommitment").mockReturnValue({
        ...epochRecord,
        publicationPolicyCommitment: malformed as never,
      });
      try {
        expect(() => harness.assertPublishedEpochEvidence(bundle)).toThrow(
          "Epoch publication policy commitment is missing or malformed",
        );
      } finally {
        malformedLedger.mockRestore();
      }
    }

    expect(() =>
      harness.assertPublishedEpochEvidence({
        ...bundle,
        epoch: {
          ...bundle.epoch,
          maintainerSignatures: [
            {
              keyId: originalSignature.keyId,
              algorithm: originalSignature.algorithm,
              signature: tamperedSignature,
            },
          ],
        },
      }),
    ).toThrow(/invalid/i);

    try {
      harness.assertPublishedEpochEvidence({
        ...bundle,
        epoch: {
          ...bundle.epoch,
          maintainerSignatures: [{
            ...originalSignature,
            signature: originalSignature.signature.slice(0, -1),
          }],
        },
      });
      throw new Error("expected malformed signature rejection");
    } catch (error) {
      expect(error).toHaveProperty("message", "Epoch maintainer signature encoding is invalid");
      expect(error).toHaveProperty("cause.message", "Jubjub signature encoding is invalid");
    }

    const malformedSequence = vi.spyOn(harness.simulator, "getEpochCommitment").mockReturnValue({
      ...epochRecord,
      publishedAtSequence: "invalid" as never,
    });
    try {
      let verifierFault: unknown;
      try {
        harness.assertPublishedEpochEvidence(bundle);
      } catch (error) {
        verifierFault = error;
      }
      expect(verifierFault).toHaveProperty("message", "Epoch maintainer signature is invalid");
      expect((verifierFault as Error).cause).toBeInstanceOf(Error);
    } finally {
      malformedSequence.mockRestore();
    }

    expect(() => harness.assertPublishedEpochEvidence({
      ...bundle,
      epoch: {
        ...bundle.epoch,
        maintainerSignatures: [{
          ...originalSignature,
          signature: `0x${"00".repeat(96)}`,
        }],
      },
    })).toThrow("Epoch maintainer signature encoding is invalid");

    expect(() => harness.assertPublishedEpochEvidence({
      ...bundle,
      epoch: {
        ...bundle.epoch,
        maintainerSignatures: [{ ...originalSignature, algorithm: "ed25519" }],
      },
    })).toThrow(/signature algorithm is unsupported/);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...bundle,
          inclusionProof: {
            ...bundle.inclusionProof,
            leafHash: `${bundle.inclusionProof.leafHash.slice(0, -1)}0`,
          },
        },
        {},
      ),
    ).toThrow(/leaf hash/i);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...bundle,
          inclusionProof: {
            ...bundle.inclusionProof,
            path: [`${bundle.inclusionProof.path[0]!.slice(0, -1)}0`],
          },
        },
        {},
      ),
    ).toThrow(/event sibling/i);
  });
});
