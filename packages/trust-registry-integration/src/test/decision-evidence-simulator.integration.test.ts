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
  SignerRole,
  VerificationRelationship,
  type Proof,
} from "@midnight-ntwrk/credential-compact";
import {
  createMidnightDIDSignerDescriptor,
  resolveMidnightDIDMethodBinding,
  signMidnightDIDCredentialProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { createCircuitContext, createConstructorContext, sampleContractAddress } from "@midnight-ntwrk/compact-runtime";
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
  pinnedVcAuthority,
  vcAuthorityDomainCommitment,
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
    const vcSchema = {
      packageId: bytes32Commitment("vc-decision-package"),
      schemaId: bytes32Commitment("vc-decision-schema"),
      majorVersion: 1n,
      minorVersion: 0n,
    };
    const scopeMapping = {
      registryScopeCommitment: candidate.scopeCommitment,
      vcScopeCommitment: pureCircuits.issuerScopeCommitment(vcSchema),
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
      signer: async ({ decisionRoot, decisionSequence, authority }) => signFixtureContextProof(
        secret, authority.verificationMethodRef, decisionRoot, decisionSequence,
        pureCircuits.signerAuthorizationProofChallenge,
      ),
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
      );
      const contractAddress = sampleContractAddress();
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
      expect(() => consumer.circuits.assertIssuerCredentialAuthorized(
        circuitContext, credential, credentialProof, signed.descriptor.authorizationId,
      )).not.toThrow();
      expect(() => consumer.circuits.assertIssuerCredentialAuthorized(
        circuitContext, credential,
        { ...credentialProof, signature: { ...credentialProof.signature, s: credentialProof.signature.s + 1n } },
        signed.descriptor.authorizationId,
      )).toThrow();
      expect(() => consumer.circuits.assertIssuerCredentialAuthorized(
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

      const verifierBinding = await resolveMidnightDIDMethodBinding({
        resolver,
        did: parseMidnightDIDString(issuer.subjectDid),
        verificationMethodId: "#assertion-1",
        relationship: "authentication",
      });
      const requestScopeCommitment = bytes32Commitment("vc-verifier-request-scope");
      const verifierDescriptor = createMidnightDIDSignerDescriptor(verifierBinding, {
        authorizationId: bytes32Commitment("vc-verifier-authorization"),
        decisionSequence: signed.descriptor.decisionSequence + 1n,
        state: AuthorizationState.active,
        role: SignerRole.verifier,
        scopeCommitment: requestScopeCommitment,
        policyCommitment: signed.descriptor.policyCommitment,
      });
      const verifierAuthorityProof = signDescriptor(verifierDescriptor);
      const verifierInstall = consumer.circuits.installSignerAuthorization(
        circuitContext, verifierDescriptor, verifierAuthorityProof,
      );
      circuitContext = createCircuitContext(
        contractAddress,
        verifierInstall.context.currentZswapLocalState,
        verifierInstall.context.currentQueryContext.state,
        verifierInstall.context.currentPrivateState,
      );
      const requestProof = signFixtureContextProof(
        seedBytesToJubjubSecretScalar(new Uint8Array(32).fill(49)),
        verifierBinding.verificationMethodRef,
        requestScopeCommitment,
        2n,
        pureCircuits.verifierRequestProofChallenge,
      );
      expect(() => consumer.circuits.assertVerifierRequestAuthorized(
        circuitContext, requestScopeCommitment, requestProof, verifierDescriptor.authorizationId,
      )).not.toThrow();
      expect(() => consumer.circuits.assertVerifierRequestAuthorized(
        circuitContext, bytes32Commitment("other-request-scope"), requestProof, verifierDescriptor.authorizationId,
      )).toThrow();
    } finally {
      await rm(output, { recursive: true, force: true });
    }

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
