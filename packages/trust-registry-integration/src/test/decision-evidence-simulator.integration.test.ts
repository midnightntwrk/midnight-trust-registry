import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";
import { AuthorizationState, pureCircuits, VerificationRelationship } from "@midnight-ntwrk/credential-compact";
import { resolveMidnightDIDMethodBinding } from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did-domain";
import {
  deriveJubjubPublicKey,
  deriveJubjubPublicKeyFromSeed,
  normalizeScalar,
  seedBytesToJubjubSecretScalar,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  assertDecisionEvidenceConsistentWithSuppliedContext,
  verifyDecisionEvidenceWithTrustedReaders,
  type DecisionEvidenceSuppliedContext,
  type TrustedDecisionEvidenceReaders,
} from "@midnight-ntwrk/trust-registry-client";
import {
  AcceptedDecisionEpochSchema,
  DecisionEvidenceSchema,
  deriveGovernancePolicySnapshot,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";

import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import {
  bytes32Commitment,
  createMidnightDid,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
} from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";
import { createVcSignerCandidateFromTrustedDecision } from "../vc-signer-candidate.js";
import {
  issueVcSignerAuthorizationFromTrustedDecision,
  vcAuthorityDomainCommitment,
  verifyVcSignerAuthorizationForConsumer,
} from "../vc-signer-authorization.js";

const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

describe("simulator-backed VC decision evidence composition", () => {
  it("matches an active issuer, complete publication quorum, and resolved Midnight DID method", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("vc-decision-composition");
    const coMaintainer = createMaintainerScenarioFixture("vc-decision-co-maintainer");
    const issuer = createIssuerScenarioFixture("vc-decision-issuer");
    harness.authorizeMaintainer(coMaintainer);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
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
    const networkId = issuer.subjectDid.split(":")[2]!;
    const contractAddress = sha256Hex("simulator:vc-decision:contract");
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
        schnorrJubjubPublicKey: subjectKey,
        verificationMethodId: "assertion-1",
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
    const evidence = DecisionEvidenceSchema.parse({
      format: "tr-decision-evidence-v1",
      role: "issuer",
      registry: { registryId: harness.registryId, registryDid: harness.registryDid, networkId, contractAddress },
      anchorReferences: {
        registryEpoch: { networkId, contractAddress, transactionHash: epochTransaction, blockHash: epochBlock },
        didState: { networkId, blockHash: didBlock },
      },
      epoch: {
        epochId: bundle.epoch.epochId,
        registryId: bundle.epoch.registryId,
        stateRoot: bundle.epoch.stateRoot,
        eventRoot: bundle.epoch.eventRoot,
        policyRoot: bundle.epoch.policyRoot,
        publicationPolicyCommitment: acceptedEpoch.publicationPolicyCommitment,
        publicationSequence: acceptedEpoch.publicationSequence,
        validFromSequence: acceptedEpoch.validFromSequence,
        validUntilSequence: acceptedEpoch.validUntilSequence,
        validFrom: bundle.epoch.validFrom,
        validUntil: bundle.epoch.validUntil,
        quorum: { requiredSignatures: acceptedEpoch.requiredSignatures, signatures: witness.signatures },
      },
      grant,
      scope: issuer.authorizationScope,
      statusPolicyBinding: bundle.statusPolicyBinding,
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
      policy: deriveGovernancePolicySnapshot(bundle.policy),
      inclusionProof: { ...bundle.inclusionProof, leafIndex: String(bundle.inclusionProof.leafIndex) },
      governanceEvents: {
        grantTransition: grant.lifecycleEventRoot,
        quorumApproval: sha256Hex("simulator:vc-decision:approval-lookup"),
        epochPublication: witness.eventHash,
        policySnapshot: bundle.epoch.policyRoot,
      },
      decisionSequence: epochRecord.publishedAtSequence.toString(),
    });
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
    expect(candidate).toMatchObject({
      role: "issuer",
      authorizationId: issuer.authorizationId,
      resourceId: issuer.resourceId,
      statusPolicyBinding: bundle.statusPolicyBinding,
      didStateVersion: stateVersion,
      publicationEventHash: witness.eventHash,
    });

    const binding = await resolveMidnightDIDMethodBinding({
      resolver,
      did: parseMidnightDIDString(issuer.subjectDid),
      verificationMethodId: "#assertion-1",
      relationship: "assertionMethod",
    });
    const scopeMapping = {
      registryScopeCommitment: candidate.scopeCommitment,
      vcScopeCommitment: pureCircuits.issuerScopeCommitment({
        packageId: bytes32Commitment("vc-decision-package"),
        schemaId: bytes32Commitment("vc-decision-schema"),
        majorVersion: 1n,
        minorVersion: 0n,
      }),
    };
    const converted = await createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers, binding, scopeMapping,
    );
    expect(converted.descriptor.decisionSequence).toBe(BigInt(epochRecord.publishedAtSequence));
    expect(converted.descriptor.didStateVersion).toBe(3n);
    expect(converted.descriptor.scopeCommitment).toEqual(scopeMapping.vcScopeCommitment);
    expect(converted.descriptor.policyCommitment).toEqual(Uint8Array.from(Buffer.from(candidate.policyRoot.slice(2), "hex")));
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers, binding,
      { ...scopeMapping, registryScopeCommitment: sha256Hex("unrelated-tr-scope") },
    )).rejects.toThrow(/scope mapping/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers,
      { ...binding, didStateVersion: 2n }, scopeMapping,
    )).rejects.toThrow(/DID state version/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers,
      { ...binding, publicKey: { ...binding.publicKey, x: binding.publicKey.x + 1n } }, scopeMapping,
    )).rejects.toThrow(/method key/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers,
      { ...binding, verificationMethodRef: {
        ...binding.verificationMethodRef,
        methodId: bytes32Commitment("other-method"),
      } }, scopeMapping,
    )).rejects.toThrow(/method binding/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers,
      { ...binding, verificationRelationship: VerificationRelationship.authentication }, scopeMapping,
    )).rejects.toThrow(/relationship/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, readers, binding,
      { ...scopeMapping, vcScopeCommitment: new Uint8Array(32) },
    )).rejects.toThrow(/VC scope commitment/u);
    await expect(createVcSignerCandidateFromTrustedDecision(
      evidence, context.selection, {
        ...readers,
        readCurrentFinalizedRegistryDecision: async () => null,
      }, binding, scopeMapping,
    )).rejects.toThrow(/registry decision is unavailable/u);

    const authoritySeed = new Uint8Array(32).fill(77);
    const authorityDid = createMidnightDid("vc-decision-authority");
    const authorityAnchor = {
      domain: {
        networkId,
        consumerContractAddress: sha256Hex("vc-decision-consumer"),
        registryId: harness.registryId,
        registryContractAddress: contractAddress,
        authorityDid,
        authorityMethodId: `${authorityDid}#authority-1`,
      },
      publicKey: deriveJubjubPublicKeyFromSeed(authoritySeed),
    };
    expect(Buffer.from(vcAuthorityDomainCommitment(authorityAnchor.domain)).toString("hex")).toBe(
      "ebf36629ff6f02534e4e6a2f5279f1ec38fdcc228c7a8183d42ab59bfdcd85ad",
    );
    const secret = seedBytesToJubjubSecretScalar(authoritySeed);
    const signed = await issueVcSignerAuthorizationFromTrustedDecision({
      evidence,
      selection: context.selection,
      readers,
      method: binding,
      scopeMapping,
      anchor: authorityAnchor,
      signer: async ({ decisionRoot, decisionSequence, authority }) => {
        const nonce = seedBytesToJubjubSecretScalar(randomBytes(32));
        const unsigned = {
          signerVerificationMethodRef: authority.verificationMethodRef,
          createdAt: decisionSequence,
          challengeHash: randomBytes(32),
          publicKey: authority.publicKey,
          signature: { r: deriveJubjubPublicKey(nonce), s: 0n },
        };
        const challenge = pureCircuits.signerAuthorizationProofChallenge(decisionRoot, unsigned);
        return { ...unsigned, signature: { r: unsigned.signature.r, s: normalizeScalar(nonce + challenge * secret) } };
      },
    });
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
  });
});
