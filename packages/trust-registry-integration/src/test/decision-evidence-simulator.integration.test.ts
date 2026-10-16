import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";
import {
  AuthorizationState,
  pureCircuits,
  VerificationRelationship,
  type Proof,
} from "@midnight-ntwrk/credential-compact";
import {
  resolveMidnightDIDMethodBinding,
  signMidnightDIDCredentialProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { createCircuitContext, createConstructorContext, encodeContractAddress, sampleContractAddress } from "@midnight-ntwrk/compact-runtime";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did-domain";
import {
  deriveJubjubPublicKey,
  deriveJubjubPublicKeyFromSeed,
  normalizeScalar,
  seedBytesToJubjubSecretScalar,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  AuthorizationStatus,
  VcAuthorityKeyStatus,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  buildDecisionEvidenceClaim,
  createVerifiedDecisionEvidenceSource,
  defaultSequenceToTimestamp,
  assertDecisionEvidenceConsistentWithSuppliedContext,
  verifyDecisionEvidenceWithTrustedReaders,
  type DecisionEvidenceSuppliedContext,
  type TrustedDecisionEvidenceReaders,
} from "@midnight-ntwrk/trust-registry-client";
import {
  AcceptedDecisionEpochSchema,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";

import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import {
  bytes32Commitment,
  createMidnightDid,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
} from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";
import { createCompactLedgerDecisionReaders } from "../compact-decision-reader.js";
import { verifyApplicationVp } from "../application-vp-verifier.js";
import { createGovernedApplicationIssuerEligibility } from "../governed-application-issuer.js";
import { createApplicationVpScenarioFixture } from "../vp-scenario-fixtures.js";
import { createVcSignerCandidateFromApi, createVcSignerCandidateFromTrustedDecision } from "../vc-signer-candidate.js";
import { createQuorumGatedVcAuthoritySigner } from "../vc-authority-signer.js";
import { issuerSchemaRefFromRegistryScope, vcScopeCommitmentFromRegistryScope } from "../vc-scope.js";
import {
  issueVcSignerAuthorizationFromApi,
  issueVcSignerAuthorizationFromTrustedDecision,
  pinnedVcAuthority,
  vcAuthorityDomainCommitment,
  vcAuthorityDomainFields,
  verifyVcSignerAuthorizationForConsumer,
} from "../vc-signer-authorization.js";

const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

const signFixtureContextProof = (
  secret: bigint,
  methodRef: Proof["signerVerificationMethodRef"],
  bodyRoot: Uint8Array,
  createdAt: bigint,
  challengeCircuit: (root: Uint8Array, proof: Proof) => bigint,
): Proof => {
  let nonce = 0n;
  while (nonce === 0n) nonce = seedBytesToJubjubSecretScalar(randomBytes(32));
  const unsigned: Proof = {
    signerVerificationMethodRef: methodRef,
    createdAt,
    challengeHash: randomBytes(32),
    publicKey: deriveJubjubPublicKey(secret),
    signature: { r: deriveJubjubPublicKey(nonce), s: 0n },
  };
  return {
    ...unsigned,
    signature: {
      r: unsigned.signature.r,
      s: normalizeScalar(nonce + challengeCircuit(bodyRoot, unsigned) * secret),
    },
  };
};

describe("simulator-backed VC decision evidence composition", () => {
  it("matches an active issuer, complete publication quorum, and resolved Midnight DID method", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("vc-decision-composition");
    const coMaintainer = createMaintainerScenarioFixture("vc-decision-co-maintainer");
    const issuer = createIssuerScenarioFixture("vc-decision-issuer");
    harness.authorizeMaintainer(coMaintainer);
    harness.authorizeMaintainer(createMaintainerScenarioFixture("vc-decision-third-maintainer"));
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const networkId = issuer.subjectDid.split(":")[2]!;
    const contractAddress = hex(encodeContractAddress(harness.simulator.contractAddress));
    const authoritySeed = new Uint8Array(32).fill(77);
    const consumerContractAddress = sampleContractAddress();
    const authorityDid = createMidnightDid("vc-decision-authority");
    const authorityAnchor = {
      domain: {
        networkId,
        consumerContractAddress: `0x${consumerContractAddress}`,
        registryId: harness.registryId,
        registryContractAddress: contractAddress,
        authorityDid,
        authorityMethodId: `${authorityDid}#authority-1`,
      },
      publicKey: deriveJubjubPublicKeyFromSeed(authoritySeed),
    };
    const authorityFields = vcAuthorityDomainFields(authorityAnchor.domain);
    const authorityKeyIdCommitment = bytes32Commitment("vc-authority:decision-key");
    harness.registerVcAuthorityKey({
      domain: authorityAnchor.domain,
      keyIdCommitment: authorityKeyIdCommitment,
      publicKey: authorityAnchor.publicKey,
    });
    harness.proposeIssuer(issuer, [coMaintainer]);
    harness.approveIssuer(issuer, [coMaintainer]);
    harness.activateIssuer(issuer, [coMaintainer]);

    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    if (bundle.authorization === undefined || bundle.statusPolicyBinding === undefined) {
      throw new Error("Expected an issuer grant and status-policy preimage");
    }
    const epochRecord = harness.simulator.getEpochCommitment(bytes32Commitment(bundle.epoch.epochId));
    const witness = harness.getEpochPublicationWitness(bundle.epoch.epochId);
    const ledger = harness.simulator.getLedger();
    const epochTransaction = sha256Hex("simulator:vc-decision:epoch-transaction");
    const epochBlock = sha256Hex("simulator:vc-decision:epoch-block");
    const didTransaction = sha256Hex("simulator:vc-decision:did-transaction");
    const didBlock = sha256Hex("simulator:vc-decision:did-block");
    const acceptedEpoch = AcceptedDecisionEpochSchema.parse({
      registryId: harness.registryId,
      registryDid: harness.registryDid,
      networkId,
      contractAddress,
      transactionHash: epochTransaction,
      blockHash: epochBlock,
      epochId: bundle.epoch.epochId,
      stateRoot: hex(epochRecord.stateRoot),
      eventRoot: hex(epochRecord.eventRoot),
      policyRoot: hex(epochRecord.policyRoot),
      publicationPolicyCommitment: hex(epochRecord.publicationPolicyCommitment),
      publicationSequence: epochRecord.publishedAtSequence.toString(),
      validFromSequence: epochRecord.validFromSequence.toString(),
      validUntilSequence: epochRecord.validUntilSequence.toString(),
      publicationEventHash: hex(epochRecord.publicationEventHash),
      validFrom: bundle.epoch.validFrom,
      validUntil: bundle.epoch.validUntil,
      requiredSignatures: Number(ledger.maintainerThreshold),
    });
    expect(witness.eventHash).toBe(acceptedEpoch.publicationEventHash);

    const subjectKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(49));
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(issuer.subjectDid, {
        schnorrJubjubAssertionMethods: [
          { id: "assertion-1", publicKey: subjectKey },
          { id: "status-1", publicKey: subjectKey },
        ],
        version: 3n,
      }),
    ]);
    const resolved = await resolver.resolveResult(issuer.subjectDid);
    if (resolved === null) throw new Error("Expected a resolved issuer DID");
    const stateVersion = resolved.didDocumentMetadata.versionId;
    if (typeof stateVersion !== "string") throw new Error("Expected a versioned issuer DID state");
    const didDocument = resolved.didDocument;
    const methodId = `${issuer.subjectDid}#assertion-1`;
    const method = didDocument.verificationMethod?.find((entry) => entry.id === methodId);
    if (method === undefined) throw new Error("Expected a native assertion method");
    expect(didDocument.assertionMethod).toContain(methodId);

    const grant = bundle.authorization;
    const buildInput = {
      bundle,
      acceptedEpoch,
      publicationSignatures: witness.signatures,
      didStateBlockHash: didBlock,
      scope: issuer.authorizationScope,
      didMethod: {
        did: issuer.subjectDid,
        methodId,
        methodType: "JsonWebKey",
        controller: issuer.subjectDid,
        publicKeyJwk: method.publicKeyJwk,
        relationship: "assertionMethod",
        stateVersion,
        stateEvidence: { evidenceType: "ledger-observation", blockHash: didBlock, transactionHash: didTransaction },
      },
      governanceEvents: {
        grantTransition: grant.lifecycleEventRoot,
        quorumApproval: sha256Hex("simulator:vc-decision:approval-lookup"),
        epochPublication: witness.eventHash,
        policySnapshot: bundle.epoch.policyRoot,
      },
      decisionSequence: epochRecord.publishedAtSequence.toString(),
    } satisfies Parameters<typeof buildDecisionEvidenceClaim>[0];
    const evidence = buildDecisionEvidenceClaim(buildInput);
    expect(() => buildDecisionEvidenceClaim({ ...buildInput,
      acceptedEpoch: { ...acceptedEpoch, stateRoot: sha256Hex("different-accepted-root") },
    })).toThrow(/accepted epoch root mismatch/u);
    expect(() => buildDecisionEvidenceClaim({ ...buildInput,
      bundle: { ...bundle, inclusionProof: { ...bundle.inclusionProof,
        leafHash: sha256Hex("different-grant-leaf") } },
    })).toThrow(/grant leaf hash mismatch/u);
    const currentGrant = harness.simulator.getCurrentIssuerAuthorization(
      issuer.subjectDidCommitment,
      issuer.resourceType,
      issuer.resourceIdCommitment,
    );
    expect(currentGrant.status).toBe(AuthorizationStatus.active);
    const context: DecisionEvidenceSuppliedContext = {
      acceptedEpoch,
      publication: {
        registryIdCommitment: harness.registryIdCommitment,
        networkIdCommitment: ledger.deploymentNetworkIdCommitment,
        contractAddress: encodeContractAddress(harness.simulator.contractAddress),
        epochIdCommitment: bytes32Commitment(bundle.epoch.epochId),
        firstSignerKeyIdCommitment: epochRecord.maintainerKeyId,
        activeMaintainersAtPublication: witness.signatures.map((signer) => {
          const keyIdCommitment = bytes32Commitment(signer.keyId);
          const maintainer = ledger.maintainerRecords.lookup(keyIdCommitment);
          return { keyId: signer.keyId, keyIdCommitment, publicKey: maintainer.publicKey };
        }),
      },
      didState: {
        networkId,
        blockHash: didBlock,
        transactionHash: didTransaction,
        stateVersion,
        deactivated: false,
        didDocument,
      },
      selection: {
        registryId: harness.registryId,
        networkId,
        contractAddress,
        subjectDid: issuer.subjectDid,
        role: "issuer",
        resourceType: grant.resourceType,
        resourceId: issuer.resourceId,
        scope: issuer.authorizationScope,
      },
      decisionPoint: {
        sequence: epochRecord.publishedAtSequence.toString(),
        evaluationTime: bundle.epoch.validFrom,
        currentPolicy: { root: hex(ledger.governancePolicyCommitment), observedAtSequence: epochRecord.publishedAtSequence.toString() },
        currentGrant: {
          authorizationId: grant.authorizationId,
          lifecycleEventRoot: hex(currentGrant.lifecycleEventHash),
          status: "active",
          observedAtSequence: epochRecord.publishedAtSequence.toString(),
        },
      },
    };
    expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, context)).not.toThrow();
    const readers: TrustedDecisionEvidenceReaders = {
      readCurrentFinalizedRegistryDecision: async (selection, epochIdHint) => {
        expect(selection).toEqual(context.selection);
        expect(epochIdHint).toBe(bundle.epoch.epochId);
        return {
          acceptedEpoch: context.acceptedEpoch,
          publication: context.publication,
          decisionPoint: context.decisionPoint,
        };
      },
      readCurrentFinalizedDidState: async (did, network, decisionSequence) => {
        expect([did, network, decisionSequence]).toEqual([
          issuer.subjectDid,
          networkId,
          epochRecord.publishedAtSequence.toString(),
        ]);
        return context.didState;
      },
    };
    const candidate = await verifyDecisionEvidenceWithTrustedReaders(evidence, context.selection, readers);
    const verifiedSource = createVerifiedDecisionEvidenceSource({
      loadCandidate: async () => ({ buildInput }),
      trustedContextFor: async () => ({ selection: context.selection, readers }),
    });
    expect(await verifiedSource("issuer", issuer.authorizationId)).toEqual(evidence);
    await expect(verifiedSource("verifier", issuer.authorizationId)).rejects.toThrow(/different grant or role/u);
    await expect(verifiedSource("issuer", "auth:unrelated")).rejects.toThrow(/different grant or role/u);
    const unavailableSource = createVerifiedDecisionEvidenceSource({
      loadCandidate: async () => ({ buildInput }),
      trustedContextFor: async () => null,
    });
    await expect(unavailableSource("issuer", issuer.authorizationId)).rejects.toThrow(/context is unavailable/u);
    const substitutedSelectionSource = createVerifiedDecisionEvidenceSource({
      loadCandidate: async () => ({ buildInput }),
      trustedContextFor: async () => ({
        selection: { ...context.selection, registryId: "registry:other" },
        readers: {
          ...readers,
          readCurrentFinalizedRegistryDecision: async () => ({
            acceptedEpoch: context.acceptedEpoch,
            publication: context.publication,
            decisionPoint: context.decisionPoint,
          }),
        },
      }),
    });
    await expect(substitutedSelectionSource("issuer", issuer.authorizationId))
      .rejects.toThrow(/registry or subject mismatch/u);
    const compactSequence = harness.simulator.getLedger().governanceActionCount.toString();
    const compactEvidence = { ...evidence, decisionSequence: compactSequence };
    const compactReaders = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: harness.simulator.getLedger(),
        acceptedEpoch: context.acceptedEpoch,
        publication: context.publication,
        evaluationTime: context.decisionPoint.evaluationTime,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      }),
      readFinalizedDidState: async (did, network, sequence) => {
        expect([did, network, sequence]).toEqual([issuer.subjectDid, networkId, compactSequence]);
        return context.didState;
      },
    });
    const compactCandidate = await verifyDecisionEvidenceWithTrustedReaders(compactEvidence, context.selection, compactReaders);
    expect(compactCandidate).toEqual({ ...candidate, decisionSequence: compactSequence });
    const wrongEpochReaders = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: harness.simulator.getLedger(),
        acceptedEpoch: { ...context.acceptedEpoch, stateRoot: sha256Hex("wrong-finalized-epoch-root") },
        publication: context.publication,
        evaluationTime: context.decisionPoint.evaluationTime,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      }),
      readFinalizedDidState: compactReaders.readCurrentFinalizedDidState,
    });
    await expect(verifyDecisionEvidenceWithTrustedReaders(
      compactEvidence, context.selection, wrongEpochReaders,
    )).rejects.toThrow(/does not match finalized Compact ledger/u);
    const wrongEpochIdReaders = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: harness.simulator.getLedger(),
        acceptedEpoch: { ...context.acceptedEpoch, epochId: "epoch:unrelated" },
        publication: context.publication,
        evaluationTime: context.decisionPoint.evaluationTime,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      }),
      readFinalizedDidState: compactReaders.readCurrentFinalizedDidState,
    });
    await expect(verifyDecisionEvidenceWithTrustedReaders(
      compactEvidence, context.selection, wrongEpochIdReaders,
    )).rejects.toThrow(/identity or epoch mismatch/u);
    const wrongNetworkLedgerReaders = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: {
          ...harness.simulator.getLedger(),
          deploymentNetworkIdCommitment: bytes32Commitment("other-network"),
        },
        acceptedEpoch: context.acceptedEpoch,
        publication: context.publication,
        evaluationTime: context.decisionPoint.evaluationTime,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      }),
      readFinalizedDidState: compactReaders.readCurrentFinalizedDidState,
    });
    await expect(verifyDecisionEvidenceWithTrustedReaders(
      compactEvidence, context.selection, wrongNetworkLedgerReaders,
    )).rejects.toThrow(/identity or epoch mismatch/u);
    const wrongPublicationNetworkReaders = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: harness.simulator.getLedger(),
        acceptedEpoch: context.acceptedEpoch,
        publication: {
          ...context.publication,
          networkIdCommitment: bytes32Commitment("other-network"),
        },
        evaluationTime: context.decisionPoint.evaluationTime,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      }),
      readFinalizedDidState: compactReaders.readCurrentFinalizedDidState,
    });
    await expect(verifyDecisionEvidenceWithTrustedReaders(
      compactEvidence, context.selection, wrongPublicationNetworkReaders,
    )).rejects.toThrow(/identity or epoch mismatch/u);
    const wrongTimeMappingReaders = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: harness.simulator.getLedger(),
        acceptedEpoch: context.acceptedEpoch,
        publication: context.publication,
        evaluationTime: context.decisionPoint.evaluationTime,
        sequenceToTimestamp: (sequence) =>
          new Date(Date.parse(defaultSequenceToTimestamp(sequence)) + 60_000).toISOString(),
      }),
      readFinalizedDidState: compactReaders.readCurrentFinalizedDidState,
    });
    await expect(verifyDecisionEvidenceWithTrustedReaders(
      compactEvidence, context.selection, wrongTimeMappingReaders,
    )).rejects.toThrow(/does not match finalized Compact ledger/u);
    const changedPolicyReaders = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: { ...harness.simulator.getLedger(), governancePolicyCommitment: bytes32Commitment("changed-policy") },
        acceptedEpoch: context.acceptedEpoch,
        publication: context.publication,
        evaluationTime: context.decisionPoint.evaluationTime,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      }),
      readFinalizedDidState: compactReaders.readCurrentFinalizedDidState,
    });
    await expect(verifyDecisionEvidenceWithTrustedReaders(
      compactEvidence, context.selection, changedPolicyReaders,
    )).rejects.toThrow(/current policy mismatch/u);
    expect(await compactReaders.readCurrentFinalizedRegistryDecision(
      context.selection, evidence.epoch.epochId, "auth:unrelated",
    )).toBeNull();
    expect(await compactReaders.readCurrentFinalizedRegistryDecision(
      { ...context.selection, role: "verifier", resourceType: "request-profile" },
      evidence.epoch.epochId, evidence.grant.authorizationId,
    )).toBeNull();
    expect(candidate).toMatchObject({
      role: "issuer",
      authorizationId: issuer.authorizationId,
      resourceId: issuer.resourceId,
      statusPolicyBinding: bundle.statusPolicyBinding,
      didStateVersion: stateVersion,
      publicationEventHash: witness.eventHash,
    });
    if (candidate.role !== "issuer") throw new Error("Expected governed issuer decision");
    const vpScenario = await createApplicationVpScenarioFixture(undefined, {
      issuerDid: issuer.subjectDid,
      issuerSecret: seedBytesToJubjubSecretScalar(new Uint8Array(32).fill(49)),
      issuerDidVersion: 3n,
      statusPolicyBinding: candidate.statusPolicyBinding,
    });
    const vpMaterial = vpScenario.material;
    const eligible = createGovernedApplicationIssuerEligibility({
      selection: context.selection,
      readers,
      loadEvidence: async () => evidence,
      allowedApplicationRoles: ["issuer", "verifier", "auditor", "maintainer"],
    });
    await expect(verifyApplicationVp({
      ...vpScenario.input,
      family: { ...vpScenario.family, assertIssuerEligible: eligible },
    })).resolves.toMatchObject({
      subjectDid: vpScenario.input.expectedSubjectDid,
      expiresAt: new Date(vpScenario.input.evaluatedAtMs + 5 * 60_000).toISOString(),
    });
    await expect(eligible(vpMaterial, vpScenario.input.scope)).resolves.toEqual(candidate.statusPolicyBinding);
    await expect(eligible({ ...vpMaterial, issuerDid: createMidnightDid("other-vp-issuer") }, vpScenario.input.scope))
      .rejects.toThrow(/not selected/u);
    await expect(eligible({ ...vpMaterial, issuerMethodId: "#other" }, vpScenario.input.scope))
      .rejects.toThrow(/issuer key/u);
    await expect(eligible({
      ...vpMaterial,
      credentialProof: {
        ...vpMaterial.credentialProof,
        publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(51)),
      },
    }, vpScenario.input.scope))
      .rejects.toThrow(/issuer key/u);
    await expect(eligible({
      ...vpMaterial,
      statusBinding: {
        ...vpMaterial.statusBinding,
        registryRef: {
          ...vpMaterial.statusBinding.registryRef,
          registryId: bytes32Commitment("substituted-status-registry"),
        },
      },
    }, vpScenario.input.scope))
      .rejects.toThrow(/status registry/u);
    const unavailableGrant = createGovernedApplicationIssuerEligibility({
      selection: context.selection,
      readers: { ...readers, readCurrentFinalizedRegistryDecision: async () => null },
      loadEvidence: async () => evidence,
      allowedApplicationRoles: ["issuer"],
    });
    await expect(unavailableGrant(vpMaterial, vpScenario.input.scope)).rejects.toThrow(/unavailable/u);
    const inactiveGrant = createGovernedApplicationIssuerEligibility({
      selection: context.selection,
      readers: {
        ...readers,
        readCurrentFinalizedRegistryDecision: async () => ({
          acceptedEpoch: context.acceptedEpoch,
          publication: context.publication,
          decisionPoint: {
            ...context.decisionPoint,
            currentGrant: { ...context.decisionPoint.currentGrant, status: "suspended" },
          },
        }),
      },
      loadEvidence: async () => evidence,
      allowedApplicationRoles: ["issuer"],
    });
    await expect(verifyApplicationVp({
      ...vpScenario.input,
      family: { ...vpScenario.family, assertIssuerEligible: inactiveGrant },
    })).rejects.toMatchObject({ category: "ineligible" });

    const binding = await resolveMidnightDIDMethodBinding({
      resolver,
      did: parseMidnightDIDString(issuer.subjectDid),
      verificationMethodId: "#assertion-1",
      relationship: "assertionMethod",
    });
    if (candidate.scope.role !== "issuer") throw new Error("Expected issuer scope");
    const vcSchema = issuerSchemaRefFromRegistryScope(candidate.scope);
    const converted = await createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers, binding,
    );
    expect(converted.descriptor.decisionSequence).toBe(BigInt(epochRecord.publishedAtSequence));
    expect(converted.descriptor.didStateVersion).toBe(3n);
    expect(converted.descriptor.scopeCommitment).toEqual(pureCircuits.issuerScopeCommitment(vcSchema));
    expect(converted.descriptor.policyCommitment).toEqual(Uint8Array.from(Buffer.from(candidate.policyRoot.slice(2), "hex")));
    const apiFetch: typeof fetch = async (url) => {
      expect(String(url)).toBe(`http://localhost:3000/v1/decision-evidence/issuer/${encodeURIComponent(issuer.authorizationId)}`);
      return new Response(JSON.stringify({ verification: "client-required", evidence }), { status: 200 });
    };
    const fromApi = await createVcSignerCandidateFromApi(
      "http://localhost:3000", issuer.authorizationId, context.selection, readers, binding, apiFetch,
    );
    expect(fromApi.descriptor).toEqual(converted.descriptor);
    await expect(createVcSignerCandidateFromApi(
      "http://localhost:3000", issuer.authorizationId, context.selection, readers, binding,
      async () => new Response(JSON.stringify({ verification: "server-verified", evidence }), { status: 200 }),
    )).rejects.toThrow(/must require client verification/u);
    await expect(createVcSignerCandidateFromApi(
      "http://localhost:3000", issuer.authorizationId, context.selection,
      { ...readers, readCurrentFinalizedRegistryDecision: async () => null }, binding, apiFetch,
    )).rejects.toThrow(/registry decision is unavailable/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers,
      { ...binding, didStateVersion: 2n },
    )).rejects.toThrow(/DID state version/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers,
      { ...binding, publicKey: { ...binding.publicKey, x: binding.publicKey.x + 1n } },
    )).rejects.toThrow(/method key/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers,
      { ...binding, verificationMethodRef: {
        ...binding.verificationMethodRef,
        methodId: bytes32Commitment("other-method"),
      } },
    )).rejects.toThrow(/method binding/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers,
      { ...binding, verificationRelationship: VerificationRelationship.authentication },
    )).rejects.toThrow(/relationship/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, {
        ...readers,
        readCurrentFinalizedRegistryDecision: async () => null,
      }, binding,
    )).rejects.toThrow(/registry decision is unavailable/u);

    const authorityResolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(authorityDid, {
        schnorrJubjubPublicKey: authorityAnchor.publicKey,
        verificationMethodId: "authority-1",
        version: 2n,
      }),
    ]);
    const authorityResolution = await authorityResolver.resolveResult(authorityDid);
    if (authorityResolution === null) throw new Error("Expected a resolved authority DID");
    const substitutedAuthorityResolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(authorityDid, {
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(78)),
        verificationMethodId: "authority-1",
        version: 3n,
      }),
    ]);
    const substitutedAuthorityResolution = await substitutedAuthorityResolver.resolveResult(authorityDid);
    if (substitutedAuthorityResolution === null) throw new Error("Expected a substituted authority DID");
    const authorityDidState = {
      networkId,
      blockHash: sha256Hex("simulator:vc-authority:did-block"),
      stateVersion: "2",
      deactivated: false,
      didDocument: authorityResolution.didDocument,
    };
    const authorityReaders: TrustedDecisionEvidenceReaders = {
      ...readers,
      readCurrentFinalizedDidState: async (did, network, decisionSequence) => {
        if (did !== authorityDid) return readers.readCurrentFinalizedDidState(did, network, decisionSequence);
        expect([network, decisionSequence]).toEqual([networkId, converted.descriptor.decisionSequence.toString()]);
        return authorityDidState;
      },
    };
    expect(vcAuthorityDomainCommitment(authorityAnchor.domain)).toHaveLength(32);
    expect(vcAuthorityDomainCommitment(authorityAnchor.domain)).not.toEqual(
      vcAuthorityDomainCommitment({
        ...authorityAnchor.domain, consumerContractAddress: sha256Hex("wrong-consumer-contract"),
      }),
    );
    const secret = seedBytesToJubjubSecretScalar(authoritySeed);
    const governedAuthorityKey = harness.simulator.getCurrentVcAuthorityKey(authorityFields.consumerContractAddress);
    expect(governedAuthorityKey.keyIdCommitment).toEqual(Uint8Array.from(authorityKeyIdCommitment));
    expect(governedAuthorityKey.status).toBe(VcAuthorityKeyStatus.active);
    expect(governedAuthorityKey.policyCommitment).toEqual(converted.descriptor.policyCommitment);
    const currentAuthorityState = {
      registryIdCommitment: harness.simulator.getLedger().registryId,
      currentPolicyCommitment: harness.simulator.getLedger().governancePolicyCommitment,
      currentPolicyVersion: harness.simulator.getLedger().governancePolicyVersion,
      currentKey: governedAuthorityKey,
    };
    const authorityKeyReader = {
      readCurrentFinalizedVcAuthorityState: async (domain: typeof authorityAnchor.domain) => {
        expect(domain).toEqual(authorityAnchor.domain);
        const ledger = harness.simulator.getLedger();
        return {
          registryIdCommitment: ledger.registryId,
          currentPolicyCommitment: ledger.governancePolicyCommitment,
          currentPolicyVersion: ledger.governancePolicyVersion,
          currentKey: harness.simulator.getCurrentVcAuthorityKey(authorityFields.consumerContractAddress),
        };
      },
    };
    let authoritySignCount = 0;
    const gatedSigner = createQuorumGatedVcAuthoritySigner({
      evidence,
      selection: context.selection,
      readers: authorityReaders,
      method: binding,
      pinnedAnchor: authorityAnchor,
      authorityKeyIdCommitment,
      authorityKeyReader,
      sign: async ({ decisionRoot, decisionSequence, authority }) => {
        authoritySignCount += 1;
        return signFixtureContextProof(
          secret, authority.verificationMethodRef, decisionRoot, decisionSequence,
          pureCircuits.signerAuthorizationProofChallenge,
        );
      },
    });
    const signed = await issueVcSignerAuthorizationFromTrustedDecision({
      evidence,
      selection: context.selection,
      readers,
      method: binding,
      anchor: authorityAnchor,
      signer: gatedSigner,
    });
    expect(authoritySignCount).toBe(1);
    const signedFromApi = await issueVcSignerAuthorizationFromApi({
      apiBase: "http://localhost:3000",
      authorizationId: issuer.authorizationId,
      selection: context.selection,
      readers,
      method: binding,
      anchor: authorityAnchor,
      signer: gatedSigner,
      fetchImpl: apiFetch,
    });
    expect(signedFromApi.descriptor).toEqual(signed.descriptor);
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signedFromApi.descriptor, signedFromApi.proof, authorityAnchor, null,
    )).not.toThrow();
    expect(authoritySignCount).toBe(2);
    await expect(issueVcSignerAuthorizationFromApi({
      apiBase: "http://localhost:3000",
      authorizationId: issuer.authorizationId,
      selection: context.selection,
      readers: { ...readers, readCurrentFinalizedRegistryDecision: async () => null },
      method: binding,
      anchor: authorityAnchor,
      signer: gatedSigner,
      fetchImpl: apiFetch,
    })).rejects.toThrow(/registry decision is unavailable/u);
    expect(authoritySignCount).toBe(2);
    const validSignerRequest = {
      decisionRoot: pureCircuits.signerAuthorizationDecisionRoot(
        signed.descriptor, pinnedVcAuthority(authorityAnchor).domainCommitment,
      ),
      decisionSequence: signed.descriptor.decisionSequence,
      authority: pinnedVcAuthority(authorityAnchor),
    };
    for (const currentState of [
      null,
      { ...currentAuthorityState, registryIdCommitment: bytes32Commitment("other-registry") },
      { ...currentAuthorityState, currentPolicyCommitment: bytes32Commitment("other-current-policy") },
      { ...currentAuthorityState, currentPolicyVersion: currentAuthorityState.currentPolicyVersion + 1n },
      { ...currentAuthorityState, currentPolicyVersion: 0n },
    ]) {
      const rejectedSigner = createQuorumGatedVcAuthoritySigner({
        evidence,
        selection: context.selection,
        readers: authorityReaders,
        method: binding,
        pinnedAnchor: authorityAnchor,
        authorityKeyIdCommitment,
        authorityKeyReader: { readCurrentFinalizedVcAuthorityState: async () => currentState },
        sign: async () => { throw new Error("Stale authority policy reached key custody"); },
      });
      await expect(rejectedSigner(validSignerRequest)).rejects.toThrow(/Current finalized VC authority key/u);
    }
    for (const currentKey of [
      null,
      { ...governedAuthorityKey, status: VcAuthorityKeyStatus.suspended },
      { ...governedAuthorityKey, keyIdCommitment: bytes32Commitment("other-key") },
      { ...governedAuthorityKey, authorityDidCommitment: bytes32Commitment("other-authority") },
      { ...governedAuthorityKey, authorityMethodIdCommitment: bytes32Commitment("other-method") },
      { ...governedAuthorityKey, networkIdCommitment: bytes32Commitment("other-network") },
      { ...governedAuthorityKey, consumerContractAddress: bytes32Commitment("other-consumer") },
      { ...governedAuthorityKey, domainCommitment: bytes32Commitment("other-domain") },
      { ...governedAuthorityKey, policyCommitment: bytes32Commitment("other-policy") },
      { ...governedAuthorityKey, policyVersion: 0n },
      { ...governedAuthorityKey, policyVersion: governedAuthorityKey.policyVersion + 1n },
      { ...governedAuthorityKey, publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(78)) },
      { ...governedAuthorityKey, registeredAtSequence: signed.descriptor.decisionSequence + 1n },
      { ...governedAuthorityKey, lastStatusSequence: signed.descriptor.decisionSequence + 1n },
    ]) {
      const rejectedSigner = createQuorumGatedVcAuthoritySigner({
        evidence,
        selection: context.selection,
        readers: authorityReaders,
        method: binding,
        pinnedAnchor: authorityAnchor,
        authorityKeyIdCommitment,
        authorityKeyReader: {
          readCurrentFinalizedVcAuthorityState: async () => ({ ...currentAuthorityState, currentKey }),
        },
        sign: async () => { throw new Error("Invalid authority reached key custody"); },
      });
      await expect(rejectedSigner(validSignerRequest)).rejects.toThrow(/Current finalized VC authority key/u);
    }
    expect(authoritySignCount).toBe(2);
    for (const currentAuthorityDidState of [
      null,
      { ...authorityDidState, deactivated: true },
      { ...authorityDidState, stateVersion: "3", didDocument: substitutedAuthorityResolution.didDocument },
      { ...authorityDidState, didDocument: {
        ...authorityDidState.didDocument,
        verificationMethod: [],
      } },
      { ...authorityDidState, didDocument: {
        ...authorityDidState.didDocument,
        assertionMethod: [],
      } },
    ]) {
      const rejectedSigner = createQuorumGatedVcAuthoritySigner({
        evidence,
        selection: context.selection,
        readers: {
          ...authorityReaders,
          readCurrentFinalizedDidState: async (did, network, sequence) => did === authorityDid
            ? currentAuthorityDidState
            : readers.readCurrentFinalizedDidState(did, network, sequence),
        },
        method: binding,
        pinnedAnchor: authorityAnchor,
        authorityKeyIdCommitment,
        authorityKeyReader,
        sign: async () => { throw new Error("Invalid authority DID reached key custody"); },
      });
      await expect(rejectedSigner(validSignerRequest)).rejects.toThrow(/authority DID/u);
    }
    expect(authoritySignCount).toBe(2);
    await expect(gatedSigner({
      decisionRoot: bytes32Commitment("substituted-decision-root"),
      decisionSequence: signed.descriptor.decisionSequence,
      authority: pinnedVcAuthority(authorityAnchor),
    })).rejects.toThrow(/does not match finalized descriptor/u);
    await expect(gatedSigner({
      ...validSignerRequest,
      authority: {
        ...validSignerRequest.authority,
        verificationMethodRef: {
          ...validSignerRequest.authority.verificationMethodRef,
          controllerAddress: { bytes: bytes32Commitment("substituted-controller") },
        },
      },
    })).rejects.toThrow(/does not match finalized descriptor/u);
    expect(authoritySignCount).toBe(2);
    await expect(gatedSigner({
      decisionRoot: pureCircuits.signerAuthorizationDecisionRoot(
        signed.descriptor, pinnedVcAuthority(authorityAnchor).domainCommitment,
      ),
      decisionSequence: signed.descriptor.decisionSequence,
      authority: pinnedVcAuthority({
        ...authorityAnchor,
        domain: { ...authorityAnchor.domain, consumerContractAddress: sha256Hex("wrong-signer-consumer") },
      }),
    })).rejects.toThrow(/does not match finalized descriptor/u);
    const staleSigner = createQuorumGatedVcAuthoritySigner({
      evidence,
      selection: context.selection,
      readers: {
        ...authorityReaders,
        readCurrentFinalizedRegistryDecision: async () => ({
          acceptedEpoch: context.acceptedEpoch,
          publication: context.publication,
          decisionPoint: {
            ...context.decisionPoint,
            currentGrant: { ...context.decisionPoint.currentGrant, status: "suspended" },
          },
        }),
      },
      method: binding,
      pinnedAnchor: authorityAnchor,
      authorityKeyIdCommitment,
      authorityKeyReader,
      sign: async () => { throw new Error("Stale decision reached key custody"); },
    });
    await expect(issueVcSignerAuthorizationFromTrustedDecision({
      evidence,
      selection: context.selection,
      readers,
      method: binding,
      anchor: authorityAnchor,
      signer: staleSigner,
    })).rejects.toThrow(/current grant mismatch/u);
    expect(authoritySignCount).toBe(2);
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signed.descriptor, signed.proof, authorityAnchor, null,
    )).not.toThrow();
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signed.descriptor, signed.proof,
      { ...authorityAnchor, domain: { ...authorityAnchor.domain, consumerContractAddress: sha256Hex("other-consumer") } },
      null,
    )).toThrow();
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signed.descriptor, signed.proof,
      { ...authorityAnchor, publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(78)) },
      null,
    )).toThrow();
    expect(() => verifyVcSignerAuthorizationForConsumer(
      { ...signed.descriptor, scopeCommitment: bytes32Commitment("other-vc-scope") },
      signed.proof, authorityAnchor, null,
    )).toThrow();
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signed.descriptor, { ...signed.proof, createdAt: signed.proof.createdAt + 1n }, authorityAnchor, null,
    )).toThrow();
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signed.descriptor, signed.proof, authorityAnchor, signed.descriptor,
    )).toThrow(/sequence must increase/u);
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signed.descriptor, signed.proof, authorityAnchor,
      { ...signed.descriptor, decisionSequence: signed.descriptor.decisionSequence - 1n },
    )).not.toThrow();
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signed.descriptor, signed.proof, authorityAnchor,
      { ...signed.descriptor, decisionSequence: signed.descriptor.decisionSequence - 1n, state: AuthorizationState.revoked },
    )).toThrow(/must remain revoked/u);
    expect(() => verifyVcSignerAuthorizationForConsumer(
      signed.descriptor, signed.proof, authorityAnchor,
      { ...signed.descriptor, decisionSequence: signed.descriptor.decisionSequence - 1n, didStateVersion: 4n },
    )).toThrow(/must not decrease/u);

    const verifier = createVerifierScenarioFixture("vc-decision-verifier");
    harness.authorizeVerifier(verifier);
    const verifierBundle = harness.evaluateCurrentVerifierDecision(verifier);
    if (verifierBundle.authorization === undefined) throw new Error("Expected an active verifier grant");
    const verifierEpochRecord = harness.simulator.getEpochCommitment(bytes32Commitment(verifierBundle.epoch.epochId));
    const verifierWitness = harness.getEpochPublicationWitness(verifierBundle.epoch.epochId);
    const verifierLedger = harness.simulator.getLedger();
    const verifierEpochTransaction = sha256Hex("simulator:vc-verifier:epoch-transaction");
    const verifierEpochBlock = sha256Hex("simulator:vc-verifier:epoch-block");
    const verifierDidTransaction = sha256Hex("simulator:vc-verifier:did-transaction");
    const verifierDidBlock = sha256Hex("simulator:vc-verifier:did-block");
    const acceptedVerifierEpoch = AcceptedDecisionEpochSchema.parse({
      registryId: harness.registryId,
      registryDid: harness.registryDid,
      networkId,
      contractAddress,
      transactionHash: verifierEpochTransaction,
      blockHash: verifierEpochBlock,
      epochId: verifierBundle.epoch.epochId,
      stateRoot: hex(verifierEpochRecord.stateRoot),
      eventRoot: hex(verifierEpochRecord.eventRoot),
      policyRoot: hex(verifierEpochRecord.policyRoot),
      publicationPolicyCommitment: hex(verifierEpochRecord.publicationPolicyCommitment),
      publicationSequence: verifierEpochRecord.publishedAtSequence.toString(),
      validFromSequence: verifierEpochRecord.validFromSequence.toString(),
      validUntilSequence: verifierEpochRecord.validUntilSequence.toString(),
      publicationEventHash: hex(verifierEpochRecord.publicationEventHash),
      validFrom: verifierBundle.epoch.validFrom,
      validUntil: verifierBundle.epoch.validUntil,
      requiredSignatures: Number(verifierLedger.maintainerThreshold),
    });
    const verifierSeed = new Uint8Array(32).fill(57);
    const verifierResolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(verifier.subjectDid, {
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(verifierSeed),
        verificationMethodId: "request-1",
        version: 4n,
      }),
    ]);
    const resolvedVerifier = await verifierResolver.resolveResult(verifier.subjectDid);
    if (resolvedVerifier === null) throw new Error("Expected a resolved verifier DID");
    const verifierVersion = resolvedVerifier.didDocumentMetadata.versionId;
    if (typeof verifierVersion !== "string") throw new Error("Expected versioned verifier DID state");
    const verifierMethodId = `${verifier.subjectDid}#request-1`;
    const verifierMethod = resolvedVerifier.didDocument.verificationMethod?.find(
      (entry) => entry.id === verifierMethodId,
    );
    if (verifierMethod === undefined) throw new Error("Expected a native verifier method");
    const verifierGrant = verifierBundle.authorization;
    const verifierScope = createVerifierAuthorizationScopeFixture(verifier);
    const verifierBuildInput = {
      bundle: verifierBundle,
      acceptedEpoch: acceptedVerifierEpoch,
      publicationSignatures: verifierWitness.signatures,
      didStateBlockHash: verifierDidBlock,
      scope: verifierScope,
      didMethod: {
        did: verifier.subjectDid,
        methodId: verifierMethodId,
        methodType: "JsonWebKey",
        controller: verifier.subjectDid,
        publicKeyJwk: verifierMethod.publicKeyJwk,
        relationship: "authentication",
        stateVersion: verifierVersion,
        stateEvidence: {
          evidenceType: "ledger-observation", blockHash: verifierDidBlock, transactionHash: verifierDidTransaction,
        },
      },
      governanceEvents: {
        grantTransition: verifierGrant.lifecycleEventRoot,
        quorumApproval: sha256Hex("simulator:vc-verifier:approval-lookup"),
        epochPublication: verifierWitness.eventHash,
        policySnapshot: verifierBundle.epoch.policyRoot,
      },
      decisionSequence: verifierEpochRecord.publishedAtSequence.toString(),
    } satisfies Parameters<typeof buildDecisionEvidenceClaim>[0];
    const verifierEvidence = buildDecisionEvidenceClaim(verifierBuildInput);
    const currentVerifierGrant = harness.simulator.getCurrentVerifierAuthorization(
      verifier.subjectDidCommitment,
      verifier.requestResourceIdCommitment,
      verifier.allowedAttributeSetCommitment,
      verifier.allowedPredicateSetCommitment,
      verifier.disclosureLevelCommitment,
    );
    const verifierSelection = {
      registryId: harness.registryId,
      networkId,
      contractAddress,
      subjectDid: verifier.subjectDid,
      role: "verifier" as const,
      resourceType: verifierGrant.resourceType,
      resourceId: verifier.scopeResourceId,
      scope: verifierScope,
    };
    const verifierReaders = {
      readCurrentFinalizedRegistryDecision: async () => ({
        acceptedEpoch: acceptedVerifierEpoch,
        publication: {
          registryIdCommitment: harness.registryIdCommitment,
          networkIdCommitment: verifierLedger.deploymentNetworkIdCommitment,
          contractAddress: encodeContractAddress(harness.simulator.contractAddress),
          epochIdCommitment: bytes32Commitment(verifierBundle.epoch.epochId),
          firstSignerKeyIdCommitment: verifierEpochRecord.maintainerKeyId,
          activeMaintainersAtPublication: verifierWitness.signatures.map((signer) => {
            const keyIdCommitment = bytes32Commitment(signer.keyId);
            const maintainer = verifierLedger.maintainerRecords.lookup(keyIdCommitment);
            return { keyId: signer.keyId, keyIdCommitment, publicKey: maintainer.publicKey };
          }),
        },
        decisionPoint: {
          sequence: verifierEpochRecord.publishedAtSequence.toString(),
          evaluationTime: verifierBundle.epoch.validFrom,
          currentPolicy: {
            root: hex(verifierLedger.governancePolicyCommitment),
            observedAtSequence: verifierEpochRecord.publishedAtSequence.toString(),
          },
          currentGrant: {
            authorizationId: verifierGrant.authorizationId,
            lifecycleEventRoot: hex(currentVerifierGrant.lifecycleEventHash),
            status: "active",
            observedAtSequence: verifierEpochRecord.publishedAtSequence.toString(),
          },
        },
      }),
      readCurrentFinalizedDidState: async () => ({
        networkId,
        blockHash: verifierDidBlock,
        transactionHash: verifierDidTransaction,
        stateVersion: verifierVersion,
        deactivated: false,
        didDocument: resolvedVerifier.didDocument,
      }),
    } satisfies TrustedDecisionEvidenceReaders;
    const verifierCandidate = await verifyDecisionEvidenceWithTrustedReaders(
      verifierEvidence, verifierSelection, verifierReaders,
    );
    const verifierSource = createVerifiedDecisionEvidenceSource({
      loadCandidate: async () => ({ buildInput: verifierBuildInput }),
      trustedContextFor: async () => ({ selection: verifierSelection, readers: verifierReaders }),
    });
    expect(await verifierSource("verifier", verifier.authorizationId)).toEqual(verifierEvidence);
    const typedVerifierSnapshotReaders: TrustedDecisionEvidenceReaders = verifierReaders;
    const verifierSnapshot = await typedVerifierSnapshotReaders.readCurrentFinalizedRegistryDecision(
      verifierSelection, verifierEvidence.epoch.epochId, verifierEvidence.grant.authorizationId,
    );
    if (verifierSnapshot === null) throw new Error("Expected a verifier snapshot");
    const verifierCompactSequence = harness.simulator.getLedger().governanceActionCount.toString();
    const verifierCompactEvidence = { ...verifierEvidence, decisionSequence: verifierCompactSequence };
    const verifierCompactReaders = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: harness.simulator.getLedger(),
        acceptedEpoch: verifierSnapshot.acceptedEpoch,
        publication: verifierSnapshot.publication,
        evaluationTime: verifierSnapshot.decisionPoint.evaluationTime,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      }),
      readFinalizedDidState: verifierReaders.readCurrentFinalizedDidState,
    });
    const verifierCompactCandidate = await verifyDecisionEvidenceWithTrustedReaders(
      verifierCompactEvidence, verifierSelection, verifierCompactReaders,
    );
    expect(verifierCompactCandidate).toEqual({ ...verifierCandidate, decisionSequence: verifierCompactSequence });
    expect(await verifierCompactReaders.readCurrentFinalizedRegistryDecision(
      { ...verifierSelection, resourceId: "request-profile:wrong" },
      verifierEvidence.epoch.epochId,
      verifierEvidence.grant.authorizationId,
    )).toBeNull();
    const verifierBinding = await resolveMidnightDIDMethodBinding({
      resolver: verifierResolver,
      did: parseMidnightDIDString(verifier.subjectDid),
      verificationMethodId: "#request-1",
      relationship: "authentication",
    });
    if (verifierCandidate.scope.role !== "verifier") throw new Error("Expected verifier scope");
    const requestScopeCommitment = vcScopeCommitmentFromRegistryScope(verifierCandidate.scope);
    const verifierSigned = await issueVcSignerAuthorizationFromTrustedDecision({
      evidence: verifierEvidence,
      selection: verifierSelection,
      readers: verifierReaders,
      method: verifierBinding,
      anchor: authorityAnchor,
      signer: async ({ decisionRoot, decisionSequence, authority }) => signFixtureContextProof(
        secret, authority.verificationMethodRef, decisionRoot, decisionSequence,
        pureCircuits.signerAuthorizationProofChallenge,
      ),
    });
    expect(verifierSigned.descriptor.didStateVersion).toBe(4n);

    const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    const cacheRoot = resolve(packageRoot, "node_modules/.cache");
    await mkdir(cacheRoot, { recursive: true });
    const output = await mkdtemp(join(cacheRoot, "vc-authority-consumer-"));
    try {
      const vcCompactRoot = dirname(fileURLToPath(import.meta.resolve(
        "@midnight-ntwrk/credential-compact/credentials/composable.compact",
      )));
      const compile = spawnSync(process.execPath, [
        resolve(packageRoot, "../../scripts/compile-compact.mjs"),
        "--skip-zk",
        "--compact-path", vcCompactRoot,
        resolve(packageRoot, "src/compact/vc-authority-consumer.compact"),
        output,
      ], { encoding: "utf8" });
      if (compile.error) throw compile.error;
      expect(compile.status, compile.stderr).toBe(0);
      const compiled = await import(pathToFileURL(join(output, "contract/index.js")).href);
      const consumer = new compiled.Contract({});
      const initial = consumer.initialState(
        createConstructorContext({}, "0".repeat(64)),
        pinnedVcAuthority(authorityAnchor),
        vcAuthorityDomainFields(authorityAnchor.domain),
      );
      const contractAddress = consumerContractAddress;
      let circuitContext = createCircuitContext(
        contractAddress,
        initial.currentZswapLocalState,
        initial.currentContractState,
        initial.currentPrivateState,
      );
      const installed = consumer.circuits.installSignerAuthorization(circuitContext, signed.descriptor, signed.proof);
      circuitContext = createCircuitContext(
        contractAddress,
        installed.context.currentZswapLocalState,
        installed.context.currentQueryContext.state,
        installed.context.currentPrivateState,
      );
      expect(compiled.ledger(circuitContext.currentQueryContext.state)
        .installedSigners.lookup(signed.descriptor.authorizationId).decisionSequence)
        .toBe(signed.descriptor.decisionSequence);
      expect(() => consumer.circuits.installSignerAuthorization(
        circuitContext, signed.descriptor, signed.proof,
      )).toThrow(/sequence must increase/u);
      const wrongAnchorContract = new compiled.Contract({});
      const wrongInitial = wrongAnchorContract.initialState(
        createConstructorContext({}, "0".repeat(64)),
        pinnedVcAuthority({
          ...authorityAnchor,
          domain: { ...authorityAnchor.domain, consumerContractAddress: sha256Hex("wrong-consumer-contract") },
        }),
        vcAuthorityDomainFields({
          ...authorityAnchor.domain, consumerContractAddress: sha256Hex("wrong-consumer-contract"),
        }),
      );
      const wrongAnchorContext = createCircuitContext(
        sampleContractAddress(),
        wrongInitial.currentZswapLocalState,
        wrongInitial.currentContractState,
        wrongInitial.currentPrivateState,
      );
      expect(() => wrongAnchorContract.circuits.installSignerAuthorization(
        wrongAnchorContext, signed.descriptor, signed.proof,
      )).toThrow();
      const replayConsumer = new compiled.Contract({});
      const replayInitial = replayConsumer.initialState(
        createConstructorContext({}, "0".repeat(64)),
        pinnedVcAuthority(authorityAnchor),
        vcAuthorityDomainFields(authorityAnchor.domain),
      );
      const replayContext = createCircuitContext(
        sampleContractAddress(),
        replayInitial.currentZswapLocalState,
        replayInitial.currentContractState,
        replayInitial.currentPrivateState,
      );
      expect(() => replayConsumer.circuits.installSignerAuthorization(
        replayContext, signed.descriptor, signed.proof,
      )).toThrow(/consumer address does not match this contract/u);
      expect(() => new compiled.Contract({}).initialState(
        createConstructorContext({}, "0".repeat(64)),
        pinnedVcAuthority(authorityAnchor),
        vcAuthorityDomainFields({
          ...authorityAnchor.domain, consumerContractAddress: sha256Hex("wrong-consumer-contract"),
        }),
      )).toThrow(/domain preimage mismatch/u);
      expect(() => consumer.circuits.installSignerAuthorization(
        circuitContext, signed.descriptor,
        { ...signed.proof, createdAt: signed.proof.createdAt + 1n },
      )).toThrow();
      const credential = {
        version: 1n,
        schema: vcSchema,
        issuerVerificationMethodRef: binding.verificationMethodRef,
        holderBinding: { holderVerificationMethodRef: {
          controllerAddress: { bytes: bytes32Commitment("vc-holder-address") },
          methodId: bytes32Commitment("vc-holder-method"),
        } },
        statusBinding: {},
        issuedAt: 1n,
        hasExpiration: false,
        expiresAt: 0n,
        claims: {},
        claimCommitments: {},
        claimRoot: bytes32Commitment("vc-decision-claim"),
      };
      const credentialProof = signMidnightDIDCredentialProof({
        methodBinding: binding,
        secretScalar: seedBytesToJubjubSecretScalar(new Uint8Array(32).fill(49)),
        bodyRoot: compiled.pureCircuits.credentialBodyRoot(credential),
        createdAt: 1n,
        challengeHash: randomBytes(32),
      });
      expect(() => consumer.circuits.assertIssuerCredentialSchemaSignerProof(
        circuitContext, credential, credentialProof, signed.descriptor.authorizationId,
      )).not.toThrow();
      expect(() => consumer.circuits.assertIssuerCredentialSchemaSignerProof(
        circuitContext, credential,
        { ...credentialProof, signature: { ...credentialProof.signature, s: credentialProof.signature.s + 1n } },
        signed.descriptor.authorizationId,
      )).toThrow();
      expect(() => consumer.circuits.assertIssuerCredentialSchemaSignerProof(
        circuitContext, { ...credential, schema: { ...vcSchema, schemaId: bytes32Commitment("wrong-schema") } },
        credentialProof, signed.descriptor.authorizationId,
      )).toThrow();

      const authority = pinnedVcAuthority(authorityAnchor);
      const signDescriptor = (descriptor: typeof signed.descriptor): Proof => signFixtureContextProof(
        secret,
        authority.verificationMethodRef,
        pureCircuits.signerAuthorizationDecisionRoot(descriptor, authority.domainCommitment),
        descriptor.decisionSequence,
        pureCircuits.signerAuthorizationProofChallenge,
      );
      const rollback = {
        ...signed.descriptor,
        decisionSequence: signed.descriptor.decisionSequence + 1n,
        didStateVersion: signed.descriptor.didStateVersion - 1n,
      };
      expect(() => consumer.circuits.installSignerAuthorization(
        circuitContext, rollback, signDescriptor(rollback),
      )).toThrow(/must not decrease/u);
      const revoked = {
        ...signed.descriptor,
        decisionSequence: signed.descriptor.decisionSequence + 1n,
        state: AuthorizationState.revoked,
      };
      const revokedInstall = consumer.circuits.installSignerAuthorization(
        circuitContext, revoked, signDescriptor(revoked),
      );
      circuitContext = createCircuitContext(
        contractAddress,
        revokedInstall.context.currentZswapLocalState,
        revokedInstall.context.currentQueryContext.state,
        revokedInstall.context.currentPrivateState,
      );
      const replay = {
        ...signed.descriptor,
        decisionSequence: revoked.decisionSequence + 1n,
      };
      expect(() => consumer.circuits.installSignerAuthorization(
        circuitContext, replay, signDescriptor(replay),
      )).toThrow(/must remain revoked/u);

      const verifierInstall = consumer.circuits.installSignerAuthorization(
        circuitContext, verifierSigned.descriptor, verifierSigned.proof,
      );
      circuitContext = createCircuitContext(
        contractAddress,
        verifierInstall.context.currentZswapLocalState,
        verifierInstall.context.currentQueryContext.state,
        verifierInstall.context.currentPrivateState,
      );
      const requestProof = signFixtureContextProof(
        seedBytesToJubjubSecretScalar(verifierSeed),
        verifierBinding.verificationMethodRef,
        requestScopeCommitment,
        2n,
        pureCircuits.verifierRequestProofChallenge,
      );
      expect(() => consumer.circuits.assertVerifierRequestAuthorized(
        circuitContext, requestScopeCommitment, requestProof, verifierSigned.descriptor.authorizationId,
      )).not.toThrow();
      expect(() => consumer.circuits.assertVerifierRequestAuthorized(
        circuitContext, bytes32Commitment("other-request-scope"), requestProof, verifierSigned.descriptor.authorizationId,
      )).toThrow();
    } finally {
      await rm(output, { recursive: true, force: true });
    }

    harness.suspendVerifier(verifier);
    const suspendedVerifier = harness.simulator.getCurrentVerifierAuthorization(
      verifier.subjectDidCommitment,
      verifier.requestResourceIdCommitment,
      verifier.allowedAttributeSetCommitment,
      verifier.allowedPredicateSetCommitment,
      verifier.disclosureLevelCommitment,
    );
    const typedVerifierReaders: TrustedDecisionEvidenceReaders = verifierReaders;
    const previousVerifierSnapshot = await typedVerifierReaders.readCurrentFinalizedRegistryDecision(
      verifierSelection, verifierEvidence.epoch.epochId, verifierEvidence.grant.authorizationId,
    );
    if (previousVerifierSnapshot === null) throw new Error("Expected the verifier decision snapshot");
    await expect(issueVcSignerAuthorizationFromTrustedDecision({
      evidence: verifierEvidence,
      selection: verifierSelection,
      readers: {
        ...verifierReaders,
        readCurrentFinalizedRegistryDecision: async () => ({
          ...previousVerifierSnapshot,
          decisionPoint: {
            ...previousVerifierSnapshot.decisionPoint,
            currentGrant: {
              ...previousVerifierSnapshot.decisionPoint.currentGrant,
              lifecycleEventRoot: hex(suspendedVerifier.lifecycleEventHash),
              status: "suspended",
            },
          },
        }),
      },
      method: verifierBinding,
      anchor: authorityAnchor,
      signer: async () => { throw new Error("Suspended grant must not reach the authority signer"); },
    })).rejects.toThrow(/current grant mismatch/u);

    expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, {
      ...context,
      didState: {
        ...context.didState,
        didDocument: { ...didDocument, assertionMethod: undefined },
      },
    })).toThrow(/relationship is absent/u);
    harness.suspendIssuer(issuer, [coMaintainer]);
    const suspended = harness.simulator.getCurrentIssuerAuthorization(
      issuer.subjectDidCommitment,
      issuer.resourceType,
      issuer.resourceIdCommitment,
    );
    expect(suspended.status).not.toBe(AuthorizationStatus.active);
    expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, {
      ...context,
      decisionPoint: {
        ...context.decisionPoint,
        currentGrant: {
          ...context.decisionPoint.currentGrant,
          lifecycleEventRoot: hex(suspended.lifecycleEventHash),
          status: "suspended",
        },
      },
    })).toThrow(/current grant mismatch/u);

    harness.suspendVcAuthorityKey(authorityKeyIdCommitment, bytes32Commitment("vc-authority:suspension-reason"));
    expect(harness.simulator.getVcAuthorityKey(authorityKeyIdCommitment).status).toBe(VcAuthorityKeyStatus.suspended);
    expect(() => harness.simulator.getCurrentVcAuthorityKey(authorityFields.consumerContractAddress)).toThrow();
    const suspendedAuthoritySigner = createQuorumGatedVcAuthoritySigner({
      evidence,
      selection: context.selection,
      readers: authorityReaders,
      method: binding,
      pinnedAnchor: authorityAnchor,
      authorityKeyIdCommitment,
      authorityKeyReader: {
        readCurrentFinalizedVcAuthorityState: async () => ({
          registryIdCommitment: harness.simulator.getLedger().registryId,
          currentPolicyCommitment: harness.simulator.getLedger().governancePolicyCommitment,
          currentPolicyVersion: harness.simulator.getLedger().governancePolicyVersion,
          currentKey: harness.simulator.getVcAuthorityKey(authorityKeyIdCommitment),
        }),
      },
      sign: async () => { throw new Error("Suspended authority reached key custody"); },
    });
    await expect(suspendedAuthoritySigner(validSignerRequest)).rejects.toThrow(/Current finalized VC authority key/u);
  }, 30_000);

  it("keeps an unchanged grant current across unrelated epochs but rejects a changed grant", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("superseded-current-epoch");
    const issuer = createIssuerScenarioFixture("superseded-current-epoch");
    harness.authorizeIssuer(issuer);
    const oldBundle = harness.evaluateCurrentIssuerDecision(issuer);
    if (oldBundle.authorization?.role !== "issuer") throw new Error("Expected issuer authorization");
    const oldRecord = harness.simulator.getEpochCommitment(bytes32Commitment(oldBundle.epoch.epochId));
    const oldWitness = harness.getEpochPublicationWitness(oldBundle.epoch.epochId);
    const newer = harness.publishRegistryEpoch("newer-current-epoch");
    const ledger = harness.simulator.getLedger();
    expect(newer.epochId).not.toBe(oldBundle.epoch.epochId);
    expect(ledger.governanceActionCount <= oldRecord.validUntilSequence).toBe(true);
    const networkId = issuer.subjectDid.split(":")[2]!;
    const contractAddress = hex(encodeContractAddress(harness.simulator.contractAddress));
    const acceptedEpoch = {
      registryId: harness.registryId,
      registryDid: harness.registryDid,
      networkId,
      contractAddress,
      transactionHash: sha256Hex("superseded:epoch-transaction"),
      blockHash: sha256Hex("superseded:epoch-block"),
      epochId: oldBundle.epoch.epochId,
      stateRoot: hex(oldRecord.stateRoot),
      eventRoot: hex(oldRecord.eventRoot),
      policyRoot: hex(oldRecord.policyRoot),
      publicationPolicyCommitment: hex(oldRecord.publicationPolicyCommitment),
      publicationSequence: oldRecord.publishedAtSequence.toString(),
      validFromSequence: oldRecord.validFromSequence.toString(),
      validUntilSequence: oldRecord.validUntilSequence.toString(),
      publicationEventHash: oldWitness.eventHash,
      validFrom: oldBundle.epoch.validFrom,
      validUntil: oldBundle.epoch.validUntil,
      requiredSignatures: Number(ledger.maintainerThreshold),
    };
    const readers = createCompactLedgerDecisionReaders({
      readFinalizedView: async () => ({
        ledger: harness.simulator.getLedger(),
        acceptedEpoch: AcceptedDecisionEpochSchema.parse(acceptedEpoch),
        publication: {
          registryIdCommitment: harness.registryIdCommitment,
          networkIdCommitment: ledger.deploymentNetworkIdCommitment,
          contractAddress: encodeContractAddress(harness.simulator.contractAddress),
          epochIdCommitment: bytes32Commitment(oldBundle.epoch.epochId),
          firstSignerKeyIdCommitment: oldRecord.maintainerKeyId,
          activeMaintainersAtPublication: [],
        },
        evaluationTime: oldBundle.epoch.validFrom,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      }),
      readFinalizedDidState: async () => { throw new Error("Stale epoch must fail before DID lookup"); },
    });
    const selection = {
      registryId: harness.registryId,
      networkId,
      contractAddress,
      subjectDid: issuer.subjectDid,
      role: "issuer" as const,
      resourceType: oldBundle.authorization.resourceType,
      resourceId: issuer.resourceId,
      scope: issuer.authorizationScope,
    };
    const current = await readers.readCurrentFinalizedRegistryDecision(
      selection, oldBundle.epoch.epochId, issuer.authorizationId,
    );
    expect(current?.decisionPoint.currentGrant.status).toBe("active");
    harness.suspendIssuer(issuer);
    await expect(readers.readCurrentFinalizedRegistryDecision(
      selection, oldBundle.epoch.epochId, issuer.authorizationId,
    )).rejects.toThrow(/stale for the current grant/u);
  }, 30_000);
});
