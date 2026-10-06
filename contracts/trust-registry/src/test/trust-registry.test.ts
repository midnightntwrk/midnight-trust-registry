import { Buffer } from "node:buffer";

import {
  computeCreateAuditorAuthorizationPayloadHash,
  computeCreateEpochCommitmentPayloadHash,
  computeCreateMaintainerMembershipPayloadHash,
  computeCreateRecognitionPayloadHash,
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeUpdateAuditorAuthorizationPayloadHash,
  computeUpdateMaintainerMembershipPayloadHash,
  computeUpdateMaintainerThresholdPolicyPayloadHash,
  computeUpdateRecognitionPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
  computeUpdateVerifierAuthorizationPayloadHash,
  computePolicyBoundActionPayloadHash,
  computePolicyBoundMaintainerActionDigest,
  deriveJubjubPublicKeyFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
  verifyPolicyBoundMaintainerAction,
} from "../signing.js";
import {
  createMaintainerFixture,
  labelToBytes32,
  type MaintainerCoAuthorizer,
  TrustRegistrySimulator,
} from "../testing.js";
import {
  AuthorizationStatus,
  IssuerResourceType,
  MaintainerStatus,
  pureCircuits,
} from "../managed/trust-registry/contract/index.js";

import { describe, expect, it } from "vitest";

const PROPOSE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:propose");
const AUTHORIZE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:authorize");
const ACTIVATE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:activate");
const SUSPEND_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:suspend");
const REVOKE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:revoke");
const ARCHIVE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:archive");
const PROPOSE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:propose");
const AUTHORIZE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:authorize");
const ACTIVATE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:activate");
const SUSPEND_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:suspend");
const REVOKE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:revoke");
const ARCHIVE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:archive");
const PROPOSE_RECOGNITION_ACTION_KIND = labelToBytes32("tr:recognition:propose");
const AUTHORIZE_RECOGNITION_ACTION_KIND = labelToBytes32("tr:recognition:authorize");
const ACTIVATE_RECOGNITION_ACTION_KIND = labelToBytes32("tr:recognition:activate");
const SUSPEND_RECOGNITION_ACTION_KIND = labelToBytes32("tr:recognition:suspend");
const REVOKE_RECOGNITION_ACTION_KIND = labelToBytes32("tr:recognition:revoke");
const ARCHIVE_RECOGNITION_ACTION_KIND = labelToBytes32("tr:recognition:archive");
const PROPOSE_AUDITOR_ACTION_KIND = labelToBytes32("tr:auditor:propose");
const AUTHORIZE_AUDITOR_ACTION_KIND = labelToBytes32("tr:auditor:authorize");
const ACTIVATE_AUDITOR_ACTION_KIND = labelToBytes32("tr:auditor:activate");
const REVOKE_AUDITOR_ACTION_KIND = labelToBytes32("tr:auditor:revoke");
const ARCHIVE_AUDITOR_ACTION_KIND = labelToBytes32("tr:auditor:archive");
const PROPOSE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:propose");
const AUTHORIZE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:authorize");
const ACTIVATE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:activate");
const SUSPEND_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:suspend");
const REVOKE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:revoke");
const ARCHIVE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:archive");
const UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND = labelToBytes32(
  "tr:policy:thresholds:update",
);
const CREATE_EPOCH_ACTION_KIND = labelToBytes32("tr:epoch:publish");

const createInitializedRegistryFixture = (seedByte: number) => {
  const simulator = new TrustRegistrySimulator();
  const registryId = labelToBytes32("registry:kanon");
  const registryDidCommitment = labelToBytes32("did:midnight:registry");
  const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
  const bootstrapMaintainer = createMaintainerFixture("bootstrap", seedByte);
  const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
    bootstrapMaintainer.seed,
  );

  simulator.initializeRegistry(
    registryId,
    registryDidCommitment,
    governancePolicyCommitment,
    bootstrapMaintainer.maintainerId,
    bootstrapMaintainer.didCommitment,
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    1n,
  );

  return {
    simulator,
    registryId,
    registryDidCommitment,
    governancePolicyCommitment,
    bootstrapMaintainer,
    bootstrapPublicKey,
  };
};

const createIssuerAuthorizationFixture = (label: string) => ({
  authorizationId: labelToBytes32(`issuer-auth:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:issuer:${label}`),
  resourceType: IssuerResourceType.credentialFamily,
  resourceId: labelToBytes32(`vc-type:${label}:v1`),
  policyId: labelToBytes32("policy:kanon:v1"),
  trustLevel: labelToBytes32("approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const activateIssuerAuthorizationFixture = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createIssuerAuthorizationFixture>,
): Uint8Array => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      payloadHash,
      simulator.getLedger().governanceActionCount,
    );

  simulator.proposeIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(PROPOSE_ISSUER_ACTION_KIND, computeCreateIssuerAuthorizationPayloadHash(
      authorization.authorizationId,
      authorization.subjectDidCommitment,
      authorization.resourceType,
      authorization.resourceId,
      authorization.policyId,
      authorization.trustLevel,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.subjectDidCommitment,
    authorization.resourceType,
    authorization.resourceId,
    authorization.policyId,
    authorization.trustLevel,
    authorization.evidenceHash,
  );
  simulator.authorizeIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(AUTHORIZE_ISSUER_ACTION_KIND, computeUpdateIssuerAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getIssuerAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
  return simulator.activateIssuerAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(ACTIVATE_ISSUER_ACTION_KIND, computeUpdateIssuerAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getIssuerAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
};

const createVerifierAuthorizationFixture = (label: string) => ({
  authorizationId: labelToBytes32(`verifier-auth:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:verifier:${label}`),
  requestProfileId: labelToBytes32(`request-profile:${label}:v1`),
  allowedAttributeSetCommitment: labelToBytes32(`attr-set:${label}:minimal`),
  allowedPredicateSetCommitment: labelToBytes32(`pred-set:${label}:adult`),
  disclosureLevelCommitment: labelToBytes32(`disclosure:${label}:selective`),
  policyId: labelToBytes32("policy:kanon:v1"),
  trustLevel: labelToBytes32("approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const createRecognitionFixture = (label: string) => ({
  recognitionId: labelToBytes32(`recognition:${label}`),
  recognizedAuthorityDidCommitment: labelToBytes32(
    `did:web:${label}.authority.example`,
  ),
  recognizedRegistryId: labelToBytes32(`registry:external:${label}:v1`),
  scopeResourceType: labelToBytes32("recognized-scope"),
  scopeResourceId: labelToBytes32(`credential-family:${label}:v1`),
  policyId: labelToBytes32("policy:kanon:v1"),
  trustLevel: labelToBytes32("peer-approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const activateVerifierAuthorizationFixture = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  authorization: ReturnType<typeof createVerifierAuthorizationFixture>,
): Uint8Array => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      payloadHash,
      simulator.getLedger().governanceActionCount,
    );
  simulator.proposeVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(PROPOSE_VERIFIER_ACTION_KIND, computeCreateVerifierAuthorizationPayloadHash(
      authorization.authorizationId,
      authorization.subjectDidCommitment,
      authorization.requestProfileId,
      authorization.allowedAttributeSetCommitment,
      authorization.allowedPredicateSetCommitment,
      authorization.disclosureLevelCommitment,
      authorization.policyId,
      authorization.trustLevel,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.subjectDidCommitment,
    authorization.requestProfileId,
    authorization.allowedAttributeSetCommitment,
    authorization.allowedPredicateSetCommitment,
    authorization.disclosureLevelCommitment,
    authorization.policyId,
    authorization.trustLevel,
    authorization.evidenceHash,
  );
  simulator.authorizeVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(AUTHORIZE_VERIFIER_ACTION_KIND, computeUpdateVerifierAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getVerifierAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
  return simulator.activateVerifierAuthorization(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(ACTIVATE_VERIFIER_ACTION_KIND, computeUpdateVerifierAuthorizationPayloadHash(
      authorization.authorizationId,
      simulator.getVerifierAuthorization(authorization.authorizationId).lifecycleEventHash,
      authorization.evidenceHash,
    )),
    authorization.authorizationId,
    authorization.evidenceHash,
  );
};

const activateRecognitionFixture = (
  registry: ReturnType<typeof createInitializedRegistryFixture>,
  recognition: ReturnType<typeof createRecognitionFixture>,
): Uint8Array => {
  const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
  const sign = (actionKind: Uint8Array, payloadHash: Uint8Array) =>
    signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      payloadHash,
      simulator.getLedger().governanceActionCount,
    );
  simulator.proposeRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(PROPOSE_RECOGNITION_ACTION_KIND, computeCreateRecognitionPayloadHash(
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    )),
    recognition.recognitionId,
    recognition.recognizedAuthorityDidCommitment,
    recognition.recognizedRegistryId,
    recognition.scopeResourceType,
    recognition.scopeResourceId,
    recognition.policyId,
    recognition.trustLevel,
    recognition.evidenceHash,
  );
  simulator.authorizeRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(AUTHORIZE_RECOGNITION_ACTION_KIND, computeUpdateRecognitionPayloadHash(
      recognition.recognitionId,
      simulator.getRecognition(recognition.recognitionId).lifecycleEventHash,
      recognition.evidenceHash,
    )),
    recognition.recognitionId,
    recognition.evidenceHash,
  );
  return simulator.activateRecognition(
    bootstrapMaintainer.keyId,
    bootstrapPublicKey,
    sign(ACTIVATE_RECOGNITION_ACTION_KIND, computeUpdateRecognitionPayloadHash(
      recognition.recognitionId,
      simulator.getRecognition(recognition.recognitionId).lifecycleEventHash,
      recognition.evidenceHash,
    )),
    recognition.recognitionId,
    recognition.evidenceHash,
  );
};

const createAuditorAuthorizationFixture = (label: string) => ({
  authorizationId: labelToBytes32(`auditor-auth:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:auditor:${label}`),
  requestProfileId: labelToBytes32(`audit-request-profile:${label}:v1`),
  allowedAttributeSetCommitment: labelToBytes32(`audit-attr-set:${label}:minimal`),
  allowedPredicateSetCommitment: labelToBytes32(`audit-pred-set:${label}:compliance`),
  disclosureLevelCommitment: labelToBytes32(`audit-disclosure:${label}:restricted`),
  policyId: labelToBytes32("policy:kanon:v1"),
  trustLevel: labelToBytes32("audit-approved"),
  evidenceHash: labelToBytes32(`evidence:${label}:create`),
});

const createMaintainerMembershipFixture = (label: string, seedByte: number) => {
  const candidate = createMaintainerFixture(label, seedByte);
  return {
    maintainerId: candidate.maintainerId,
    maintainerDidCommitment: candidate.didCommitment,
    keyId: candidate.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(candidate.seed),
    policyId: labelToBytes32("policy:kanon:v1"),
    trustLevel: labelToBytes32("governance-approved"),
    evidenceHash: labelToBytes32(`evidence:${label}:propose`),
    seed: candidate.seed,
  };
};

const createMaintainerCoAuthorizer = (
  maintainer: ReturnType<typeof createMaintainerMembershipFixture>,
  simulator: TrustRegistrySimulator,
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: maintainer.publicKey,
  signature: signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    registryId,
    simulator.getLedger().governancePolicyCommitment,
    actionKind,
    actionPayloadHash,
    actionSequence,
  ),
});

const createEpochCommitmentFixture = (label: string, policyRoot: Uint8Array) => ({
  epochId: labelToBytes32(`epoch:${label}`),
  stateRoot: labelToBytes32(`state-root:${label}`),
  eventRoot: labelToBytes32(`event-root:${label}`),
  policyRoot,
  validFromSequence: 1n,
  validUntilSequence: 61n,
});

describe("trust registry contract", () => {
  it("binds action payload hashes to a nonempty policy commitment", () => {
    const policyV1 = labelToBytes32("policy:snapshot:v1");
    const policyV2 = labelToBytes32("policy:snapshot:v2");
    const payload = labelToBytes32("action:payload");
    const bound = computePolicyBoundActionPayloadHash(policyV1, payload);

    expect(bound).toEqual(pureCircuits.policyBoundActionPayloadHash(policyV1, payload));
    expect(Buffer.from(bound).toString("hex")).not.toBe(
      Buffer.from(computePolicyBoundActionPayloadHash(policyV2, payload)).toString("hex"),
    );
    expect(Buffer.from(bound).toString("hex")).not.toBe(
      Buffer.from(computePolicyBoundActionPayloadHash(policyV1, labelToBytes32("other"))).toString("hex"),
    );
    expect(() => computePolicyBoundActionPayloadHash(new Uint8Array(32), payload)).toThrow(
      /policy commitment must be set/i,
    );
    expect(() => computePolicyBoundActionPayloadHash(policyV1, payload.subarray(1))).toThrow(
      /action payload hash must be 32 bytes/i,
    );
  });

  it("signs the four-field action digest under one explicit policy snapshot", () => {
    const maintainer = createMaintainerFixture("policy-bound", 19);
    const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
    const registryId = labelToBytes32("registry:policy-bound");
    const policyV1 = labelToBytes32("policy:snapshot:v1");
    const policyV2 = labelToBytes32("policy:snapshot:v2");
    const actionKind = labelToBytes32("tr:issuer:propose");
    const payload = labelToBytes32("issuer:proposal:payload");
    const signature = signPolicyBoundMaintainerActionFromSeed(
      maintainer.seed,
      registryId,
      policyV1,
      actionKind,
      payload,
      3n,
    );

    expect(computePolicyBoundMaintainerActionDigest(
      registryId, policyV1, actionKind, payload, 3n,
    )).toHaveLength(4);
    expect(verifyPolicyBoundMaintainerAction(
      publicKey, registryId, policyV1, actionKind, payload, 3n, signature,
    )).toBe(true);
    expect(verifyPolicyBoundMaintainerAction(
      publicKey, registryId, policyV2, actionKind, payload, 3n, signature,
    )).toBe(false);
  });

  it("accepts valid threshold rules and rejects invalid ones", () => {
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 2n)).not.toThrow();
    expect(() =>
      pureCircuits.assertValidMaintainerThresholdPolicy(3n, 2n, 1n, 1n),
    ).not.toThrow();
    expect(() => pureCircuits.assertValidMaintainerThreshold(0n, 1n)).toThrow(
      /at least 1/i,
    );
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 4n)).toThrow(
      /may not exceed/i,
    );
    expect(() => pureCircuits.assertValidMaintainerThreshold(8n, 8n)).toThrow(
      /supported signer-set capacity/i,
    );
    expect(() =>
      pureCircuits.assertSingleSignatureMaintainerThreshold(3n, 2n),
    ).toThrow(/requires threshold 1/i);
  });

  it("initializes the registry with a bootstrap maintainer and records the initial governance event", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 7);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    simulator.initializeRegistry(
      registryId,
      registryDidCommitment,
      governancePolicyCommitment,
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const state = simulator.getLedger();
    const maintainer = state.maintainerRecords.lookup(bootstrapMaintainer.keyId);

    expect(state.initialized).toBe(true);
    expect(state.contractVersion).toBe(1n);
    expect(Buffer.from(state.registryId)).toEqual(Buffer.from(registryId));
    expect(Buffer.from(state.registryDidCommitment)).toEqual(
      Buffer.from(registryDidCommitment),
    );
    expect(Buffer.from(state.governancePolicyCommitment)).toEqual(
      Buffer.from(governancePolicyCommitment),
    );
    expect(state.maintainerThreshold).toEqual(1n);
    expect(state.emergencyMaintainerThreshold).toEqual(1n);
    expect(state.archivalMaintainerThreshold).toEqual(1n);
    expect(state.activeMaintainerCount).toEqual(1n);
    expect(state.governanceActionCount).toEqual(1n);
    expect(state.governanceEventHashes.member(state.lastGovernanceEventHash)).toBe(
      true,
    );
    expect(maintainer.status).toEqual(MaintainerStatus.active);
    expect(Buffer.from(maintainer.keyId)).toEqual(
      Buffer.from(bootstrapMaintainer.keyId),
    );
  });

  it("rejects invalid initialization payloads and repeated initialization", () => {
    const simulator = new TrustRegistrySimulator();
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 9);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    expect(() =>
      simulator.initializeRegistry(
        new Uint8Array(32),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        1n,
      ),
    ).toThrow(/Registry id must be set/);

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon"),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        0n,
      ),
    ).toThrow(/threshold must be at least 1/i);

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon"),
        labelToBytes32("did:midnight:registry"),
        labelToBytes32("policy:kanon:v1"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        2n,
      ),
    ).toThrow(/may not exceed active maintainer count/i);

    simulator.initializeRegistry(
      labelToBytes32("registry:kanon"),
      labelToBytes32("did:midnight:registry"),
      labelToBytes32("policy:kanon:v1"),
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon:second"),
        labelToBytes32("did:midnight:registry:second"),
        labelToBytes32("policy:kanon:v2"),
        bootstrapMaintainer.maintainerId,
        bootstrapMaintainer.didCommitment,
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        1n,
      ),
    ).toThrow(/already been initialized/i);
  });

  it("governs maintainer membership through proposal, approval, activation, suspension, revocation, and archival", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(11);
    const candidate = createMaintainerMembershipFixture("governed", 12);

    const proposeActionSequence = simulator.getLedger().governanceActionCount;
    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        candidate.maintainerDidCommitment,
        candidate.keyId,
        candidate.publicKey,
        candidate.policyId,
        candidate.trustLevel,
        candidate.evidenceHash,
      ),
      proposeActionSequence,
    );

    simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeSignature,
      candidate.maintainerId,
      candidate.maintainerDidCommitment,
      candidate.keyId,
      candidate.publicKey,
      candidate.policyId,
      candidate.trustLevel,
      candidate.evidenceHash,
    );

    const proposedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(proposedMembership.status).toEqual(AuthorizationStatus.proposed);

    const authorizeEvidenceHash = candidate.evidenceHash;
    const authorizeActionSequence = simulator.getLedger().governanceActionCount;
    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        proposedMembership.lifecycleEventHash,
        authorizeEvidenceHash,
      ),
      authorizeActionSequence,
    );

    simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      candidate.maintainerId,
      authorizeEvidenceHash,
    );

    const authorizedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(authorizedMembership.status).toEqual(AuthorizationStatus.authorized);

    const activateEvidenceHash = candidate.evidenceHash;
    const activateActionSequence = simulator.getLedger().governanceActionCount;
    const activateSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        authorizedMembership.lifecycleEventHash,
        activateEvidenceHash,
      ),
      activateActionSequence,
    );

    simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      candidate.maintainerId,
      activateEvidenceHash,
    );

    const activeMembership = simulator.getCurrentMaintainerMembership(
      candidate.maintainerDidCommitment,
    );
    const activeMaintainer = simulator.getLedger().maintainerRecords.lookup(
      candidate.keyId,
    );
    expect(activeMembership.status).toEqual(AuthorizationStatus.active);
    expect(activeMaintainer.status).toEqual(MaintainerStatus.active);
    expect(simulator.getLedger().activeMaintainerCount).toEqual(2n);

    const suspendEvidenceHash = labelToBytes32("evidence:governed:suspend");
    const suspendActionSequence = simulator.getLedger().governanceActionCount;
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        activeMembership.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      suspendActionSequence,
    );

    simulator.suspendMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      candidate.maintainerId,
      suspendEvidenceHash,
    );

    const suspendedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(suspendedMembership.status).toEqual(AuthorizationStatus.suspended);
    expect(simulator.getLedger().activeMaintainerCount).toEqual(1n);

    const revokeEvidenceHash = labelToBytes32("evidence:governed:revoke");
    const revokeActionSequence = simulator.getLedger().governanceActionCount;
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        suspendedMembership.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      revokeActionSequence,
    );

    simulator.revokeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      candidate.maintainerId,
      revokeEvidenceHash,
    );

    const revokedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(revokedMembership.status).toEqual(AuthorizationStatus.revoked);
    expect(
      simulator.getLedger().maintainerRecords.lookup(candidate.keyId).status,
    ).toEqual(MaintainerStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:governed:archive");
    const archiveActionSequence = simulator.getLedger().governanceActionCount;
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        candidate.maintainerId,
        revokedMembership.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      archiveActionSequence,
    );

    simulator.archiveMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      candidate.maintainerId,
      archiveEvidenceHash,
    );

    const archivedMembership = simulator.getMaintainerMembership(
      candidate.maintainerId,
    );
    expect(archivedMembership.status).toEqual(AuthorizationStatus.archived);
    expect(
      simulator.getLedger().maintainerRecords.lookup(candidate.keyId).status,
    ).toEqual(MaintainerStatus.archived);
  });

  it("rejects duplicate live maintainer identity enrollment and protects the last active maintainer from deactivation", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(13);
    const selfCandidate = createMaintainerMembershipFixture("self", 14);
    selfCandidate.maintainerDidCommitment = bootstrapMaintainer.didCommitment;

    const proposeActionSequence = simulator.getLedger().governanceActionCount;
    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        selfCandidate.maintainerId,
        selfCandidate.maintainerDidCommitment,
        selfCandidate.keyId,
        selfCandidate.publicKey,
        selfCandidate.policyId,
        selfCandidate.trustLevel,
        selfCandidate.evidenceHash,
      ),
      proposeActionSequence,
    );

    expect(() =>
      simulator.proposeMaintainerMembership(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        proposeSignature,
        selfCandidate.maintainerId,
        selfCandidate.maintainerDidCommitment,
        selfCandidate.keyId,
        selfCandidate.publicKey,
        selfCandidate.policyId,
        selfCandidate.trustLevel,
        selfCandidate.evidenceHash,
      ),
    ).toThrow(/already has a live membership/i);

    const suspendEvidenceHash = labelToBytes32("evidence:bootstrap:suspend");
    const suspendActionSequence = simulator.getLedger().governanceActionCount;
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        bootstrapMaintainer.maintainerId,
        simulator.getMaintainerMembership(bootstrapMaintainer.maintainerId)
          .lifecycleEventHash,
        suspendEvidenceHash,
      ),
      suspendActionSequence,
    );

    expect(() =>
      simulator.suspendMaintainerMembership(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        suspendSignature,
        bootstrapMaintainer.maintainerId,
        suspendEvidenceHash,
      ),
    ).toThrow(/threshold policy/i);
  });

  it("authorizes a signed maintainer action for the bootstrap maintainer", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const registryDidCommitment = labelToBytes32("did:midnight:registry");
    const governancePolicyCommitment = labelToBytes32("policy:kanon:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 3);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );

    simulator.initializeRegistry(
      registryId,
      registryDidCommitment,
      governancePolicyCommitment,
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const actionKind = labelToBytes32("tr:authorize:issuer");
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );

    expect(
      verifyPolicyBoundMaintainerAction(
        bootstrapPublicKey,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        actionKind,
        actionPayloadHash,
        actionSequence,
        signature,
      ),
    ).toBe(true);

    const eventHash = simulator.authorizeMaintainerAction(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      actionKind,
      actionPayloadHash,
    );
    const state = simulator.getLedger();

    expect(Buffer.from(eventHash)).toEqual(Buffer.from(state.lastGovernanceEventHash));
    expect(Buffer.from(eventHash)).toEqual(Buffer.from(pureCircuits.governanceEventHash(
      registryId,
      governancePolicyCommitment,
      state.lastAuthorizedSignerSetHash,
      actionKind,
      actionPayloadHash,
      actionSequence,
    )));
    expect(state.governanceEventHashes.member(state.lastGovernanceEventHash)).toBe(
      true,
    );
    expect(state.governanceActionCount).toEqual(2n);
    expect(Buffer.from(state.lastAuthorizedActionKind)).toEqual(
      Buffer.from(actionKind),
    );
    expect(Buffer.from(state.lastAuthorizedActionPayloadHash)).toEqual(
      Buffer.from(actionPayloadHash),
    );
    expect(Buffer.from(state.lastAuthorizedMaintainerKeyId)).toEqual(
      Buffer.from(bootstrapMaintainer.keyId),
    );
  });

  it("updates quorum thresholds and enforces scoped multi-maintainer execution", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(15);
    const secondMaintainer = createMaintainerMembershipFixture("second", 16);

    const proposeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const proposeMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        secondMaintainer.maintainerDidCommitment,
        secondMaintainer.keyId,
        secondMaintainer.publicKey,
        secondMaintainer.policyId,
        secondMaintainer.trustLevel,
        secondMaintainer.evidenceHash,
      ),
      proposeMaintainerSequence,
    );
    simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeMaintainerSignature,
      secondMaintainer.maintainerId,
      secondMaintainer.maintainerDidCommitment,
      secondMaintainer.keyId,
      secondMaintainer.publicKey,
      secondMaintainer.policyId,
      secondMaintainer.trustLevel,
      secondMaintainer.evidenceHash,
    );

    const authorizeMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const authorizeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const authorizeMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        simulator.getMaintainerMembership(secondMaintainer.maintainerId)
          .lifecycleEventHash,
        authorizeMaintainerEvidenceHash,
      ),
      authorizeMaintainerSequence,
    );
    simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeMaintainerSignature,
      secondMaintainer.maintainerId,
      authorizeMaintainerEvidenceHash,
    );

    const activateMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const activateMaintainerSequence = simulator.getLedger().governanceActionCount;
    const activateMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        simulator.getMaintainerMembership(secondMaintainer.maintainerId)
          .lifecycleEventHash,
        activateMaintainerEvidenceHash,
      ),
      activateMaintainerSequence,
    );
    simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateMaintainerSignature,
      secondMaintainer.maintainerId,
      activateMaintainerEvidenceHash,
    );

    const invalidThresholdPolicySequence = simulator.getLedger().governanceActionCount;
    const invalidThresholdPolicySignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        simulator.getLedger().governancePolicyCommitment,
        labelToBytes32("policy:kanon:v2"),
        2n,
        3n,
        1n,
        1n,
      ),
      invalidThresholdPolicySequence,
    );
    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        invalidThresholdPolicySignature,
        labelToBytes32("policy:kanon:v2"),
        2n,
        3n,
        1n,
        1n,
      ),
    ).toThrow(/may not exceed active maintainer count/i);

    const thresholdPolicySequence = simulator.getLedger().governanceActionCount;
    const thresholdPolicyPayloadHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      simulator.getLedger().governancePolicyCommitment,
      labelToBytes32("policy:kanon:v2"),
      2n,
      2n,
      1n,
      2n,
    );
    const thresholdPolicySignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      thresholdPolicyPayloadHash,
      thresholdPolicySequence,
    );
    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        labelToBytes32("policy:kanon:unsigned"),
        2n,
        2n,
        1n,
        2n,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);
    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        simulator.getLedger().governancePolicyCommitment,
        2n,
        2n,
        1n,
        2n,
      ),
    ).toThrow(/must not reuse/i);
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      thresholdPolicySignature,
      labelToBytes32("policy:kanon:v2"),
      2n,
      2n,
      1n,
      2n,
    );

    expect(simulator.getLedger().maintainerThreshold).toEqual(2n);
    expect(simulator.getLedger().emergencyMaintainerThreshold).toEqual(1n);
    expect(simulator.getLedger().archivalMaintainerThreshold).toEqual(2n);
    expect(simulator.getLedger().governancePolicyVersion).toEqual(2n);
    expect(Buffer.from(simulator.getLedger().governancePolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:kanon:v2")),
    );
    expect(Buffer.from(simulator.getLedger().lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:kanon:v1")),
    );
    expect(
      Buffer.from(simulator.getLedger().governancePolicyCommitmentsByVersion.lookup(1n)),
    ).toEqual(Buffer.from(labelToBytes32("policy:kanon:v1")));
    expect(
      Buffer.from(simulator.getLedger().governancePolicyCommitmentsByVersion.lookup(2n)),
    ).toEqual(Buffer.from(labelToBytes32("policy:kanon:v2")));
    expect(simulator.getLedger().governancePolicyEffectiveFromByVersion.lookup(2n)).toEqual(
      thresholdPolicySequence + 1n,
    );

    expect(() =>
      simulator.updateMaintainerThresholdPolicy(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        thresholdPolicySignature,
        labelToBytes32("unused-policy-commitment"),
        2n,
        2n,
        1n,
        2n,
      ),
    ).toThrow(/version must increase/i);

    const issuer = createIssuerAuthorizationFixture("quorum");
    const proposedEvidenceHash = labelToBytes32("evidence:quorum:issuer:propose");
    const proposeIssuerPayloadHash = computeCreateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      issuer.subjectDidCommitment,
      issuer.resourceType,
      issuer.resourceId,
      issuer.policyId,
      issuer.trustLevel,
      proposedEvidenceHash,
    );

    const singleSignerSequence = simulator.getLedger().governanceActionCount;
    const singleSignerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      singleSignerSequence,
    );
    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        singleSignerSignature,
        issuer.authorizationId,
        issuer.subjectDidCommitment,
        issuer.resourceType,
        issuer.resourceId,
        issuer.policyId,
        issuer.trustLevel,
        proposedEvidenceHash,
      ),
    ).toThrow(/must satisfy the action threshold/i);

    const proposeIssuerSequence = simulator.getLedger().governanceActionCount;
    const proposeIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    const secondIssuerProposer = createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    const stalePolicySignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      labelToBytes32("policy:kanon:v1"),
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        stalePolicySignature,
        issuer.authorizationId,
        issuer.subjectDidCommitment,
        issuer.resourceType,
        issuer.resourceId,
        issuer.policyId,
        issuer.trustLevel,
        proposedEvidenceHash,
        [secondIssuerProposer],
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);
    simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeIssuerSignature,
      issuer.authorizationId,
      issuer.subjectDidCommitment,
      issuer.resourceType,
      issuer.resourceId,
      issuer.policyId,
      issuer.trustLevel,
      proposedEvidenceHash,
      [secondIssuerProposer],
    );
    expect(Buffer.from(simulator.getLedger().lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(labelToBytes32("policy:kanon:v2")),
    );

    const authorizeIssuerEvidenceHash = proposedEvidenceHash;
    const authorizeIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
      authorizeIssuerEvidenceHash,
    );
    const authorizeIssuerSequence = simulator.getLedger().governanceActionCount;
    const authorizeIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      authorizeIssuerPayloadHash,
      authorizeIssuerSequence,
    );
    const secondIssuerAuthorizer = createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      AUTHORIZE_ISSUER_ACTION_KIND,
      authorizeIssuerPayloadHash,
      authorizeIssuerSequence,
    );
    simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeIssuerSignature,
      issuer.authorizationId,
      authorizeIssuerEvidenceHash,
      [secondIssuerAuthorizer],
    );

    const activateIssuerEvidenceHash = proposedEvidenceHash;
    const activateIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
      activateIssuerEvidenceHash,
    );
    const activateIssuerSequence = simulator.getLedger().governanceActionCount;
    const activateIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_ISSUER_ACTION_KIND,
      activateIssuerPayloadHash,
      activateIssuerSequence,
    );
    const secondIssuerActivator = createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      ACTIVATE_ISSUER_ACTION_KIND,
      activateIssuerPayloadHash,
      activateIssuerSequence,
    );
    simulator.activateIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateIssuerSignature,
      issuer.authorizationId,
      activateIssuerEvidenceHash,
      [secondIssuerActivator],
    );

    const suspendedIssuerEvidenceHash = labelToBytes32(
      "evidence:quorum:issuer:suspend",
    );
    const suspendIssuerSequence = simulator.getLedger().governanceActionCount;
    const suspendIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuer.authorizationId,
        simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
        suspendedIssuerEvidenceHash,
      ),
      suspendIssuerSequence,
    );
    simulator.suspendIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendIssuerSignature,
      issuer.authorizationId,
      suspendedIssuerEvidenceHash,
    );

    expect(simulator.getIssuerAuthorization(issuer.authorizationId).status).toEqual(
      AuthorizationStatus.suspended,
    );

    const archivedIssuerEvidenceHash = labelToBytes32(
      "evidence:quorum:issuer:archive",
    );
    const archiveIssuerPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      simulator.getIssuerAuthorization(issuer.authorizationId).lifecycleEventHash,
      archivedIssuerEvidenceHash,
    );
    const archiveIssuerSequence = simulator.getLedger().governanceActionCount;
    const archiveIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      archiveIssuerPayloadHash,
      archiveIssuerSequence,
    );
    expect(() =>
      simulator.archiveIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        archiveIssuerSignature,
        issuer.authorizationId,
        archivedIssuerEvidenceHash,
      ),
    ).toThrow(/must satisfy the action threshold/i);

    const secondIssuerArchiver = createMaintainerCoAuthorizer(
      secondMaintainer,
      simulator,
      registryId,
      ARCHIVE_ISSUER_ACTION_KIND,
      archiveIssuerPayloadHash,
      archiveIssuerSequence,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveIssuerSignature,
      issuer.authorizationId,
      archivedIssuerEvidenceHash,
      [secondIssuerArchiver],
    );

    expect(simulator.getIssuerAuthorization(issuer.authorizationId).status).toEqual(
      AuthorizationStatus.archived,
    );
  });

  it("rejects duplicate maintainer signers in quorum execution", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(17);
    const secondMaintainer = createMaintainerMembershipFixture("duplicate", 18);

    const proposeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const proposeMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        secondMaintainer.maintainerDidCommitment,
        secondMaintainer.keyId,
        secondMaintainer.publicKey,
        secondMaintainer.policyId,
        secondMaintainer.trustLevel,
        secondMaintainer.evidenceHash,
      ),
      proposeMaintainerSequence,
    );
    simulator.proposeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeMaintainerSignature,
      secondMaintainer.maintainerId,
      secondMaintainer.maintainerDidCommitment,
      secondMaintainer.keyId,
      secondMaintainer.publicKey,
      secondMaintainer.policyId,
      secondMaintainer.trustLevel,
      secondMaintainer.evidenceHash,
    );

    const authorizeMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const authorizeMaintainerSequence = simulator.getLedger().governanceActionCount;
    const authorizeMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        simulator.getMaintainerMembership(secondMaintainer.maintainerId)
          .lifecycleEventHash,
        authorizeMaintainerEvidenceHash,
      ),
      authorizeMaintainerSequence,
    );
    simulator.authorizeMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeMaintainerSignature,
      secondMaintainer.maintainerId,
      authorizeMaintainerEvidenceHash,
    );

    const activateMaintainerEvidenceHash = secondMaintainer.evidenceHash;
    const activateMaintainerSequence = simulator.getLedger().governanceActionCount;
    const activateMaintainerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        secondMaintainer.maintainerId,
        simulator.getMaintainerMembership(secondMaintainer.maintainerId)
          .lifecycleEventHash,
        activateMaintainerEvidenceHash,
      ),
      activateMaintainerSequence,
    );
    simulator.activateMaintainerMembership(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateMaintainerSignature,
      secondMaintainer.maintainerId,
      activateMaintainerEvidenceHash,
    );

    const thresholdPolicySequence = simulator.getLedger().governanceActionCount;
    const thresholdPolicySignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        simulator.getLedger().governancePolicyCommitment,
        labelToBytes32("policy:kanon:v2"),
        2n,
        2n,
        1n,
        1n,
      ),
      thresholdPolicySequence,
    );
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      thresholdPolicySignature,
      labelToBytes32("policy:kanon:v2"),
      2n,
      2n,
      1n,
      1n,
    );

    const issuer = createIssuerAuthorizationFixture("duplicate-quorum");
    const proposedEvidenceHash = labelToBytes32(
      "evidence:duplicate:issuer:propose",
    );
    const proposeIssuerPayloadHash = computeCreateIssuerAuthorizationPayloadHash(
      issuer.authorizationId,
      issuer.subjectDidCommitment,
      issuer.resourceType,
      issuer.resourceId,
      issuer.policyId,
      issuer.trustLevel,
      proposedEvidenceHash,
    );
    const proposeIssuerSequence = simulator.getLedger().governanceActionCount;
    const proposeIssuerSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      proposeIssuerPayloadHash,
      proposeIssuerSequence,
    );
    const duplicateBootstrapAuthorizer: MaintainerCoAuthorizer = {
      keyId: bootstrapMaintainer.keyId,
      publicKey: bootstrapPublicKey,
      signature: signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_ISSUER_ACTION_KIND,
        proposeIssuerPayloadHash,
        proposeIssuerSequence,
      ),
    };

    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        proposeIssuerSignature,
        issuer.authorizationId,
        issuer.subjectDidCommitment,
        issuer.resourceType,
        issuer.resourceId,
        issuer.policyId,
        issuer.trustLevel,
        proposedEvidenceHash,
        [duplicateBootstrapAuthorizer],
      ),
    ).toThrow(/must not contain duplicates/i);
  });

  it("rejects maintainer actions before initialization and rejects tampered authorization", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const actionKind = labelToBytes32("tr:authorize:issuer");
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 5);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );
    const signatureBeforeInit = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      labelToBytes32("policy:kanon:v1"),
      actionKind,
      actionPayloadHash,
      0n,
    );

    expect(() =>
      simulator.authorizeMaintainerAction(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signatureBeforeInit,
        actionKind,
        actionPayloadHash,
      ),
    ).toThrow(/not initialized/i);

    simulator.initializeRegistry(
      registryId,
      labelToBytes32("did:midnight:registry"),
      labelToBytes32("policy:kanon:v1"),
      bootstrapMaintainer.maintainerId,
      bootstrapMaintainer.didCommitment,
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const actionSequence = simulator.getLedger().governanceActionCount;
    const validSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );
    const tamperedSignature = {
      ...validSignature,
      response: validSignature.response + 1n,
    };

    expect(() =>
      simulator.authorizeMaintainerAction(
        labelToBytes32("maintainer:wrong"),
        bootstrapPublicKey,
        validSignature,
        actionKind,
        actionPayloadHash,
      ),
    ).toThrow(/not registered/i);

    expect(() =>
      simulator.authorizeMaintainerAction(
        bootstrapMaintainer.keyId,
        deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(19)),
        validSignature,
        actionKind,
        actionPayloadHash,
      ),
    ).toThrow(/does not match the registered key/i);

    expect(() =>
      simulator.authorizeMaintainerAction(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedSignature,
        actionKind,
        actionPayloadHash,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);
  });

  it("creates and queries an active issuer authorization by id and scope", () => {
    const registry = createInitializedRegistryFixture(17);
    const { simulator } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("birth");
    const eventHash = activateIssuerAuthorizationFixture(registry, issuerAuthorization);
    const state = simulator.getLedger();
    const recordById = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    const recordByScope = simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    );

    expect(state.issuerAuthorizationCount).toEqual(1n);
    expect(state.activeIssuerAuthorizationCount).toEqual(1n);
    expect(recordById.status).toEqual(AuthorizationStatus.active);
    expect(recordById.resourceType).toEqual(
      IssuerResourceType.credentialFamily,
    );
    expect(Buffer.from(recordById.authorizationId)).toEqual(
      Buffer.from(issuerAuthorization.authorizationId),
    );
    expect(Buffer.from(recordById.lifecycleEventHash)).toEqual(
      Buffer.from(eventHash),
    );
    expect(Buffer.from(recordByScope.authorizationId)).toEqual(
      Buffer.from(issuerAuthorization.authorizationId),
    );
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).not.toThrow();
  });

  it("moves an issuer authorization through proposed, authorized, and active states", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(19);
    const issuerAuthorization = createIssuerAuthorizationFixture("application");
    const proposalEvidenceHash = labelToBytes32("evidence:application:propose");
    const proposalSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.trustLevel,
        proposalEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    const proposalEventHash = simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposalSignature,
      issuerAuthorization.authorizationId,
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
      issuerAuthorization.policyId,
      issuerAuthorization.trustLevel,
      proposalEvidenceHash,
    );
    const proposedRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );

    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(proposedRecord.authorizedAtSequence).toEqual(0n);
    expect(proposedRecord.activeFromSequence).toEqual(0n);
    expect(simulator.getLedger().issuerAuthorizationCount).toEqual(1n);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
    expect(Buffer.from(proposedRecord.lifecycleEventHash)).toEqual(
      Buffer.from(proposalEventHash),
    );
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).toThrow(/not active/i);

    const mismatchedEvidenceHash = labelToBytes32("evidence:application:mismatched");
    const mismatchedAuthorizationSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        mismatchedEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() =>
      simulator.authorizeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        mismatchedAuthorizationSignature,
        issuerAuthorization.authorizationId,
        mismatchedEvidenceHash,
      ),
    ).toThrow(/must match the proposed application/i);

    const authorizationEvidenceHash = proposalEvidenceHash;
    const authorizationSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        authorizationEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    const authorizationEventHash = simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizationSignature,
      issuerAuthorization.authorizationId,
      authorizationEvidenceHash,
    );
    const authorizedRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );

    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(authorizedRecord.authorizedAtSequence).toBeGreaterThan(
      proposedRecord.proposedAtSequence,
    );
    expect(authorizedRecord.activeFromSequence).toEqual(0n);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
    expect(Buffer.from(authorizedRecord.lifecycleEventHash)).toEqual(
      Buffer.from(authorizationEventHash),
    );
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).toThrow(/not active/i);

    const activationEvidenceHash = proposalEvidenceHash;
    const activationSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        activationEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    const activationEventHash = simulator.activateIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activationSignature,
      issuerAuthorization.authorizationId,
      activationEvidenceHash,
    );
    const activeRecord = simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    );

    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(activeRecord.activeFromSequence).toBeGreaterThan(
      authorizedRecord.authorizedAtSequence,
    );
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(1n);
    expect(Buffer.from(activeRecord.lifecycleEventHash)).toEqual(
      Buffer.from(activationEventHash),
    );
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).not.toThrow();
  });

  it("archives proposed issuer applications and revokes authorized issuer applications before activation", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(21);
    const archivedProposal = createIssuerAuthorizationFixture("archivable");
    const revocableAuthorization = createIssuerAuthorizationFixture("revocable");

    const archivedProposalSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        archivedProposal.authorizationId,
        archivedProposal.subjectDidCommitment,
        archivedProposal.resourceType,
        archivedProposal.resourceId,
        archivedProposal.policyId,
        archivedProposal.trustLevel,
        archivedProposal.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archivedProposalSignature,
      archivedProposal.authorizationId,
      archivedProposal.subjectDidCommitment,
      archivedProposal.resourceType,
      archivedProposal.resourceId,
      archivedProposal.policyId,
      archivedProposal.trustLevel,
      archivedProposal.evidenceHash,
    );
    const proposedRecord = simulator.getIssuerAuthorization(
      archivedProposal.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:archivable:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        archivedProposal.authorizationId,
        proposedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      archivedProposal.authorizationId,
      archiveEvidenceHash,
    );
    expect(
      simulator.getIssuerAuthorization(archivedProposal.authorizationId).status,
    ).toEqual(AuthorizationStatus.archived);

    const revocableProposalSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        revocableAuthorization.authorizationId,
        revocableAuthorization.subjectDidCommitment,
        revocableAuthorization.resourceType,
        revocableAuthorization.resourceId,
        revocableAuthorization.policyId,
        revocableAuthorization.trustLevel,
        revocableAuthorization.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revocableProposalSignature,
      revocableAuthorization.authorizationId,
      revocableAuthorization.subjectDidCommitment,
      revocableAuthorization.resourceType,
      revocableAuthorization.resourceId,
      revocableAuthorization.policyId,
      revocableAuthorization.trustLevel,
      revocableAuthorization.evidenceHash,
    );
    const revocableProposedRecord = simulator.getIssuerAuthorization(
      revocableAuthorization.authorizationId,
    );
    const authorizeEvidenceHash = revocableAuthorization.evidenceHash;
    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        revocableAuthorization.authorizationId,
        revocableProposedRecord.lifecycleEventHash,
        authorizeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      revocableAuthorization.authorizationId,
      authorizeEvidenceHash,
    );
    const authorizedRecord = simulator.getIssuerAuthorization(
      revocableAuthorization.authorizationId,
    );
    const revokeEvidenceHash = labelToBytes32("evidence:revocable:revoke");
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        revocableAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      revocableAuthorization.authorizationId,
      revokeEvidenceHash,
    );

    expect(
      simulator.getIssuerAuthorization(revocableAuthorization.authorizationId)
        .status,
    ).toEqual(AuthorizationStatus.revoked);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
  });

  it("suspends, revokes, and archives issuer authorizations while preserving append-only scope state", () => {
    const registry = createInitializedRegistryFixture(23);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("degree");
    activateIssuerAuthorizationFixture(registry, issuerAuthorization);

    const createdRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    const suspendEvidenceHash = labelToBytes32("evidence:degree:suspend");
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.suspendIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      issuerAuthorization.authorizationId,
      suspendEvidenceHash,
    );

    const suspendedRecord = simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    );
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
    expect(() =>
      simulator.assertIssuerAuthorized(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:degree:revoke");
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      issuerAuthorization.authorizationId,
      revokeEvidenceHash,
    );

    const revokedRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:degree:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      issuerAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    const archivedRecord = simulator.getCurrentIssuerAuthorization(
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
    );
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect(simulator.getLedger().activeIssuerAuthorizationCount).toEqual(0n);
  });

  it("rejects duplicate issuer scope proposals, invalid transitions, tampered signatures, and missing queries", () => {
    const registry = createInitializedRegistryFixture(29);
    const { simulator, registryId, bootstrapMaintainer, bootstrapPublicKey } = registry;
    const issuerAuthorization = createIssuerAuthorizationFixture("license");

    expect(() =>
      simulator.getIssuerAuthorization(labelToBytes32("issuer-auth:missing")),
    ).toThrow(/not registered/i);
    expect(() =>
      simulator.getCurrentIssuerAuthorization(
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
      ),
    ).toThrow(/scope is not registered/i);

    const proposalPayloadHash = computeCreateIssuerAuthorizationPayloadHash(
      issuerAuthorization.authorizationId,
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
      issuerAuthorization.policyId,
      issuerAuthorization.trustLevel,
      issuerAuthorization.evidenceHash,
    );
    const tamperedProposalSignature = {
      ...signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_ISSUER_ACTION_KIND,
        proposalPayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };

    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedProposalSignature,
        issuerAuthorization.authorizationId,
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.trustLevel,
        issuerAuthorization.evidenceHash,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);

    const proposalAuthorizationId = labelToBytes32("issuer-auth:license:proposal");
    const proposalEvidenceHash = labelToBytes32("evidence:license:proposal");
    const proposalSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        proposalAuthorizationId,
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.trustLevel,
        proposalEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposalSignature,
      proposalAuthorizationId,
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
      issuerAuthorization.policyId,
      issuerAuthorization.trustLevel,
      proposalEvidenceHash,
    );

    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signPolicyBoundMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          PROPOSE_ISSUER_ACTION_KIND,
          computeCreateIssuerAuthorizationPayloadHash(
            labelToBytes32("issuer-auth:license:proposal:duplicate"),
            issuerAuthorization.subjectDidCommitment,
            issuerAuthorization.resourceType,
            issuerAuthorization.resourceId,
            issuerAuthorization.policyId,
            issuerAuthorization.trustLevel,
            labelToBytes32("evidence:license:proposal:duplicate"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        labelToBytes32("issuer-auth:license:proposal:duplicate"),
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.trustLevel,
        labelToBytes32("evidence:license:proposal:duplicate"),
      ),
    ).toThrow(/live authorization/i);

    expect(() =>
      simulator.activateIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signPolicyBoundMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          ACTIVATE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            proposalAuthorizationId,
            simulator.getIssuerAuthorization(proposalAuthorizationId)
              .lifecycleEventHash,
            labelToBytes32("evidence:license:activate"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        proposalAuthorizationId,
        labelToBytes32("evidence:license:activate"),
      ),
    ).toThrow(/must be authorized/i);

    const activeIssuerAuthorization = createIssuerAuthorizationFixture("license-active");
    activateIssuerAuthorizationFixture(registry, activeIssuerAuthorization);

    expect(() =>
      simulator.proposeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signPolicyBoundMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          PROPOSE_ISSUER_ACTION_KIND,
          computeCreateIssuerAuthorizationPayloadHash(
            labelToBytes32("issuer-auth:license-active:duplicate"),
            activeIssuerAuthorization.subjectDidCommitment,
            activeIssuerAuthorization.resourceType,
            activeIssuerAuthorization.resourceId,
            activeIssuerAuthorization.policyId,
            activeIssuerAuthorization.trustLevel,
            labelToBytes32("evidence:license-active:duplicate"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        labelToBytes32("issuer-auth:license-active:duplicate"),
        activeIssuerAuthorization.subjectDidCommitment,
        activeIssuerAuthorization.resourceType,
        activeIssuerAuthorization.resourceId,
        activeIssuerAuthorization.policyId,
        activeIssuerAuthorization.trustLevel,
        labelToBytes32("evidence:license-active:duplicate"),
      ),
    ).toThrow(/live authorization/i);

    expect(() =>
      simulator.authorizeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signPolicyBoundMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          AUTHORIZE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            activeIssuerAuthorization.authorizationId,
            simulator.getIssuerAuthorization(
              activeIssuerAuthorization.authorizationId,
            ).lifecycleEventHash,
            labelToBytes32("evidence:license-active:authorize"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        activeIssuerAuthorization.authorizationId,
        labelToBytes32("evidence:license-active:authorize"),
      ),
    ).toThrow(/must be proposed/i);

    const createdRecord = simulator.getIssuerAuthorization(
      activeIssuerAuthorization.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:license:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        activeIssuerAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      activeIssuerAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    expect(() =>
      simulator.revokeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signPolicyBoundMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          REVOKE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            activeIssuerAuthorization.authorizationId,
            simulator.getIssuerAuthorization(
              activeIssuerAuthorization.authorizationId,
            ).lifecycleEventHash,
            labelToBytes32("evidence:license:revoke"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        activeIssuerAuthorization.authorizationId,
        labelToBytes32("evidence:license:revoke"),
      ),
    ).toThrow(/authorized, active, or suspended/i);
  });

  it("creates and queries an active verifier authorization with predicate and disclosure scoped lookups", () => {
    const registry = createInitializedRegistryFixture(31);
    const {
      simulator,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("age-gate");
    const eventHash = activateVerifierAuthorizationFixture(registry, verifierAuthorization);
    const state = simulator.getLedger();
    const recordById = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const recordByScope = simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestProfileId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    );

    expect(state.verifierAuthorizationCount).toEqual(1n);
    expect(state.activeVerifierAuthorizationCount).toEqual(1n);
    expect(recordById.status).toEqual(AuthorizationStatus.active);
    expect(Buffer.from(recordById.authorizationId)).toEqual(
      Buffer.from(verifierAuthorization.authorizationId),
    );
    expect(Buffer.from(recordById.lifecycleEventHash)).toEqual(
      Buffer.from(eventHash),
    );
    expect(Buffer.from(recordByScope.authorizationId)).toEqual(
      Buffer.from(verifierAuthorization.authorizationId),
    );
    expect(() =>
      simulator.assertVerifierAuthorized(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      ),
    ).not.toThrow();
    expect(() =>
      simulator.getCurrentVerifierAuthorization(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        labelToBytes32("pred-set:age-gate:different"),
        verifierAuthorization.disclosureLevelCommitment,
      ),
    ).toThrow(/scope is not registered/i);
  });

  it("moves a verifier authorization through proposed, authorized, and active states", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(35);
    const verifierAuthorization = createVerifierAuthorizationFixture("employment-application");
    const proposalEvidenceHash = labelToBytes32("evidence:employment:proposal");

    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_VERIFIER_ACTION_KIND,
      computeCreateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
        verifierAuthorization.policyId,
        verifierAuthorization.trustLevel,
        proposalEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeSignature,
      verifierAuthorization.authorizationId,
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestProfileId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
      verifierAuthorization.policyId,
      verifierAuthorization.trustLevel,
      proposalEvidenceHash,
    );

    const proposedRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);

    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        proposalEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      verifierAuthorization.authorizationId,
      proposalEvidenceHash,
    );

    const authorizedRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);

    const activateSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        proposalEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      verifierAuthorization.authorizationId,
      proposalEvidenceHash,
    );

    const activeRecord = simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestProfileId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    );
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(1n);
  });

  it("suspends, revokes, and archives verifier authorizations while preserving scope-sensitive state", () => {
    const registry = createInitializedRegistryFixture(37);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("university");
    activateVerifierAuthorizationFixture(registry, verifierAuthorization);

    const createdRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const suspendEvidenceHash = labelToBytes32("evidence:university:suspend");
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.suspendVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      verifierAuthorization.authorizationId,
      suspendEvidenceHash,
    );

    const suspendedRecord = simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestProfileId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    );
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);
    expect(() =>
      simulator.assertVerifierAuthorized(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      ),
    ).toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:university:revoke");
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      verifierAuthorization.authorizationId,
      revokeEvidenceHash,
    );

    const revokedRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:university:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      verifierAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    const archivedRecord = simulator.getCurrentVerifierAuthorization(
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestProfileId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
    );
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);
  });

  it("rejects duplicate verifier scopes, invalid transitions, tampered signatures, and missing verifier queries", () => {
    const registry = createInitializedRegistryFixture(41);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const verifierAuthorization = createVerifierAuthorizationFixture("passport");

    expect(() =>
      simulator.getVerifierAuthorization(labelToBytes32("verifier-auth:missing")),
    ).toThrow(/not registered/i);
    expect(() =>
      simulator.getCurrentVerifierAuthorization(
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
      ),
    ).toThrow(/scope is not registered/i);

    const proposePayloadHash = computeCreateVerifierAuthorizationPayloadHash(
      verifierAuthorization.authorizationId,
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestProfileId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
      verifierAuthorization.policyId,
      verifierAuthorization.trustLevel,
      verifierAuthorization.evidenceHash,
    );
    const tamperedProposeSignature = {
      ...signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_VERIFIER_ACTION_KIND,
        proposePayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };
    expect(() => simulator.proposeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      tamperedProposeSignature,
      verifierAuthorization.authorizationId,
      verifierAuthorization.subjectDidCommitment,
      verifierAuthorization.requestProfileId,
      verifierAuthorization.allowedAttributeSetCommitment,
      verifierAuthorization.allowedPredicateSetCommitment,
      verifierAuthorization.disclosureLevelCommitment,
      verifierAuthorization.policyId,
      verifierAuthorization.trustLevel,
      verifierAuthorization.evidenceHash,
    )).toThrow(/invalid jubjub schnorr signature/i);

    activateVerifierAuthorizationFixture(registry, verifierAuthorization);
    const duplicate = {
      ...verifierAuthorization,
      authorizationId: labelToBytes32("verifier-auth:passport:duplicate"),
      evidenceHash: labelToBytes32("evidence:passport:duplicate"),
    };
    expect(() => simulator.proposeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_VERIFIER_ACTION_KIND,
        computeCreateVerifierAuthorizationPayloadHash(
          duplicate.authorizationId,
          duplicate.subjectDidCommitment,
          duplicate.requestProfileId,
          duplicate.allowedAttributeSetCommitment,
          duplicate.allowedPredicateSetCommitment,
          duplicate.disclosureLevelCommitment,
          duplicate.policyId,
          duplicate.trustLevel,
          duplicate.evidenceHash,
        ),
        simulator.getLedger().governanceActionCount,
      ),
      duplicate.authorizationId,
      duplicate.subjectDidCommitment,
      duplicate.requestProfileId,
      duplicate.allowedAttributeSetCommitment,
      duplicate.allowedPredicateSetCommitment,
      duplicate.disclosureLevelCommitment,
      duplicate.policyId,
      duplicate.trustLevel,
      duplicate.evidenceHash,
    )).toThrow(/live authorization/i);
    const createdRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:passport:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      verifierAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    expect(() =>
      simulator.revokeVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signPolicyBoundMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          REVOKE_VERIFIER_ACTION_KIND,
          computeUpdateVerifierAuthorizationPayloadHash(
            verifierAuthorization.authorizationId,
            simulator.getVerifierAuthorization(verifierAuthorization.authorizationId)
              .lifecycleEventHash,
            labelToBytes32("evidence:passport:revoke"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        verifierAuthorization.authorizationId,
        labelToBytes32("evidence:passport:revoke"),
      ),
    ).toThrow(/authorized, active, or suspended/i);
  });

  it("creates and queries an active recognition by id and scope", () => {
    const registry = createInitializedRegistryFixture(43);
    const {
      simulator,
    } = registry;
    const recognition = createRecognitionFixture("gaia-x");
    const eventHash = activateRecognitionFixture(registry, recognition);
    const state = simulator.getLedger();
    const recordById = simulator.getRecognition(recognition.recognitionId);
    const recordByScope = simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    );

    expect(state.recognitionCount).toEqual(1n);
    expect(state.activeRecognitionCount).toEqual(1n);
    expect(recordById.status).toEqual(AuthorizationStatus.active);
    expect(Buffer.from(recordById.recognitionId)).toEqual(
      Buffer.from(recognition.recognitionId),
    );
    expect(Buffer.from(recordById.lifecycleEventHash)).toEqual(
      Buffer.from(eventHash),
    );
    expect(Buffer.from(recordByScope.recognitionId)).toEqual(
      Buffer.from(recognition.recognitionId),
    );
    expect(() =>
      simulator.assertRecognitionActive(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      ),
    ).not.toThrow();
  });

  it("moves a recognition through proposed, authorized, and active states", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(45);
    const recognition = createRecognitionFixture("gaia-x-application");
    const proposedEvidenceHash = labelToBytes32("evidence:gaia-x-application:propose");
    const replacementEvidenceHash = labelToBytes32("evidence:gaia-x-application:replacement");

    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_RECOGNITION_ACTION_KIND,
      computeCreateRecognitionPayloadHash(
        recognition.recognitionId,
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
        recognition.policyId,
        recognition.trustLevel,
        proposedEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeSignature,
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      proposedEvidenceHash,
    );

    const proposedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);

    const replacementAuthorizeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        proposedRecord.lifecycleEventHash,
        replacementEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() => simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      replacementAuthorizeSignature,
      recognition.recognitionId,
      replacementEvidenceHash,
    )).toThrow(/evidence must match the proposed application/i);
    expect(simulator.getRecognition(recognition.recognitionId).status).toEqual(
      AuthorizationStatus.proposed,
    );

    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        proposedRecord.lifecycleEventHash,
        proposedEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      recognition.recognitionId,
      proposedEvidenceHash,
    );

    const authorizedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);

    const replacementActivateSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        authorizedRecord.lifecycleEventHash,
        replacementEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() => simulator.activateRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      replacementActivateSignature,
      recognition.recognitionId,
      replacementEvidenceHash,
    )).toThrow(/activation evidence must match the proposed application/i);
    expect(simulator.getRecognition(recognition.recognitionId).status).toEqual(
      AuthorizationStatus.authorized,
    );

    const activateSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        authorizedRecord.lifecycleEventHash,
        proposedEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      recognition.recognitionId,
      proposedEvidenceHash,
    );

    const activeRecord = simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    );
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(1n);
  });

  it("suspends, revokes, and archives recognition records while preserving append-only scope state", () => {
    const registry = createInitializedRegistryFixture(47);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const recognition = createRecognitionFixture("eidas");
    activateRecognitionFixture(registry, recognition);

    const createdRecord = simulator.getRecognition(recognition.recognitionId);
    const suspendEvidenceHash = labelToBytes32("evidence:eidas:suspend");
    const suspendSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      SUSPEND_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        createdRecord.lifecycleEventHash,
        suspendEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.suspendRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      suspendSignature,
      recognition.recognitionId,
      suspendEvidenceHash,
    );

    const suspendedRecord = simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    );
    expect(suspendedRecord.status).toEqual(AuthorizationStatus.suspended);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);
    expect(() =>
      simulator.assertRecognitionActive(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      ),
    ).toThrow(/not active/i);

    const revokeEvidenceHash = labelToBytes32("evidence:eidas:revoke");
    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        suspendedRecord.lifecycleEventHash,
        revokeEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      recognition.recognitionId,
      revokeEvidenceHash,
    );

    const revokedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(revokedRecord.status).toEqual(AuthorizationStatus.revoked);

    const archiveEvidenceHash = labelToBytes32("evidence:eidas:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        revokedRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      recognition.recognitionId,
      archiveEvidenceHash,
    );

    const archivedRecord = simulator.getCurrentRecognition(
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
    );
    expect(archivedRecord.status).toEqual(AuthorizationStatus.archived);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);
  });

  it("rejects duplicate recognition scopes, invalid transitions, tampered signatures, and missing recognition queries", () => {
    const registry = createInitializedRegistryFixture(53);
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = registry;
    const recognition = createRecognitionFixture("gaia-net");

    expect(() =>
      simulator.getRecognition(labelToBytes32("recognition:missing")),
    ).toThrow(/not registered/i);
    expect(() =>
      simulator.getCurrentRecognition(
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
      ),
    ).toThrow(/scope is not registered/i);

    const proposePayloadHash = computeCreateRecognitionPayloadHash(
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    );
    const tamperedProposeSignature = {
      ...signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_RECOGNITION_ACTION_KIND,
        proposePayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };
    expect(() => simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      tamperedProposeSignature,
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    )).toThrow(/invalid jubjub schnorr signature/i);

    activateRecognitionFixture(registry, recognition);
    const duplicate = {
      ...recognition,
      recognitionId: labelToBytes32("recognition:gaia-net:duplicate"),
      evidenceHash: labelToBytes32("evidence:gaia-net:duplicate"),
    };
    expect(() => simulator.proposeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        PROPOSE_RECOGNITION_ACTION_KIND,
        computeCreateRecognitionPayloadHash(
          duplicate.recognitionId,
          duplicate.recognizedAuthorityDidCommitment,
          duplicate.recognizedRegistryId,
          duplicate.scopeResourceType,
          duplicate.scopeResourceId,
          duplicate.policyId,
          duplicate.trustLevel,
          duplicate.evidenceHash,
        ),
        simulator.getLedger().governanceActionCount,
      ),
      duplicate.recognitionId,
      duplicate.recognizedAuthorityDidCommitment,
      duplicate.recognizedRegistryId,
      duplicate.scopeResourceType,
      duplicate.scopeResourceId,
      duplicate.policyId,
      duplicate.trustLevel,
      duplicate.evidenceHash,
    )).toThrow(/live recognition/i);
    const createdRecord = simulator.getRecognition(recognition.recognitionId);
    const archiveEvidenceHash = labelToBytes32("evidence:gaia-net:archive");
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      recognition.recognitionId,
      archiveEvidenceHash,
    );

    expect(() =>
      simulator.revokeRecognition(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signPolicyBoundMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          REVOKE_RECOGNITION_ACTION_KIND,
          computeUpdateRecognitionPayloadHash(
            recognition.recognitionId,
            simulator.getRecognition(recognition.recognitionId)
              .lifecycleEventHash,
            labelToBytes32("evidence:gaia-net:revoke"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        recognition.recognitionId,
        labelToBytes32("evidence:gaia-net:revoke"),
      ),
    ).toThrow(/authorized, active, or suspended/i);
  });

  it("creates and governs auditor authorizations across proposal, activation, and archival paths", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(57);
    const auditorAuthorization = createAuditorAuthorizationFixture("iso-27001");

    const proposeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      PROPOSE_AUDITOR_ACTION_KIND,
      computeCreateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        auditorAuthorization.subjectDidCommitment,
        auditorAuthorization.requestProfileId,
        auditorAuthorization.allowedAttributeSetCommitment,
        auditorAuthorization.allowedPredicateSetCommitment,
        auditorAuthorization.disclosureLevelCommitment,
        auditorAuthorization.policyId,
        auditorAuthorization.trustLevel,
        labelToBytes32("evidence:iso-27001:propose"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.proposeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      proposeSignature,
      auditorAuthorization.authorizationId,
      auditorAuthorization.subjectDidCommitment,
      auditorAuthorization.requestProfileId,
      auditorAuthorization.allowedAttributeSetCommitment,
      auditorAuthorization.allowedPredicateSetCommitment,
      auditorAuthorization.disclosureLevelCommitment,
      auditorAuthorization.policyId,
      auditorAuthorization.trustLevel,
      labelToBytes32("evidence:iso-27001:propose"),
    );

    const proposedRecord = simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    );
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);

    const authorizeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      AUTHORIZE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        proposedRecord.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      auditorAuthorization.authorizationId,
      proposedRecord.evidenceHash,
    );

    const authorizedRecord = simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    );
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);

    const activateSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ACTIVATE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        authorizedRecord.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      auditorAuthorization.authorizationId,
      authorizedRecord.evidenceHash,
    );

    const activeRecord = simulator.getCurrentAuditorAuthorization(
      auditorAuthorization.subjectDidCommitment,
      auditorAuthorization.requestProfileId,
      auditorAuthorization.allowedAttributeSetCommitment,
      auditorAuthorization.allowedPredicateSetCommitment,
      auditorAuthorization.disclosureLevelCommitment,
    );
    expect(activeRecord.status).toEqual(AuthorizationStatus.active);
    expect(simulator.getLedger().activeAuditorAuthorizationCount).toEqual(1n);
    expect(() =>
      simulator.assertAuditorAuthorized(
        auditorAuthorization.subjectDidCommitment,
        auditorAuthorization.requestProfileId,
        auditorAuthorization.allowedAttributeSetCommitment,
        auditorAuthorization.allowedPredicateSetCommitment,
        auditorAuthorization.disclosureLevelCommitment,
      ),
    ).not.toThrow();

    const revokeSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      REVOKE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        activeRecord.lifecycleEventHash,
        labelToBytes32("evidence:iso-27001:revoke"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.revokeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revokeSignature,
      auditorAuthorization.authorizationId,
      labelToBytes32("evidence:iso-27001:revoke"),
    );
    expect(simulator.getLedger().activeAuditorAuthorizationCount).toEqual(0n);

    const revokedRecord = simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    );
    const archiveSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      ARCHIVE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        revokedRecord.lifecycleEventHash,
        labelToBytes32("evidence:iso-27001:archive"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      auditorAuthorization.authorizationId,
      labelToBytes32("evidence:iso-27001:archive"),
    );
    expect(
      simulator.getAuditorAuthorization(auditorAuthorization.authorizationId).status,
    ).toEqual(AuthorizationStatus.archived);
  });

  it("publishes and queries an epoch commitment by id and latest pointer", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(59);
    const epoch = createEpochCommitmentFixture(
      "seq-1",
      simulator.getLedger().governancePolicyCommitment,
    );
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
      actionSequence,
    );

    const eventHash = simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      epoch.epochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      epoch.validFromSequence,
      epoch.validUntilSequence,
    );
    const state = simulator.getLedger();
    const recordById = simulator.getEpochCommitment(epoch.epochId);
    const recordByLatest = simulator.getCurrentEpochCommitment();

    expect(state.epochCommitmentCount).toEqual(1n);
    expect(Buffer.from(state.latestEpochCommitmentId)).toEqual(
      Buffer.from(epoch.epochId),
    );
    expect(Buffer.from(recordById.epochId)).toEqual(Buffer.from(epoch.epochId));
    expect(Buffer.from(recordById.stateRoot)).toEqual(Buffer.from(epoch.stateRoot));
    expect(Buffer.from(recordById.eventRoot)).toEqual(Buffer.from(epoch.eventRoot));
    expect(Buffer.from(recordById.policyRoot)).toEqual(
      Buffer.from(epoch.policyRoot),
    );
    expect(Buffer.from(recordById.publicationPolicyCommitment)).toEqual(
      Buffer.from(state.governancePolicyCommitment),
    );
    expect(recordById.validFromSequence).toEqual(epoch.validFromSequence);
    expect(recordById.validUntilSequence).toEqual(epoch.validUntilSequence);
    expect(Buffer.from(recordById.publicationEventHash)).toEqual(
      Buffer.from(eventHash),
    );
    expect(Buffer.from(recordByLatest.epochId)).toEqual(Buffer.from(epoch.epochId));
    expect(recordByLatest.signatureResponse).toEqual(signature.response);
  });

  it("rejects missing epoch queries, invalid epoch windows, tampered signatures, and duplicate epoch ids", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(61);
    const epoch = createEpochCommitmentFixture(
      "seq-2",
      simulator.getLedger().governancePolicyCommitment,
    );

    expect(() => simulator.getCurrentEpochCommitment()).toThrow(
      /no epoch commitment/i,
    );
    expect(() =>
      simulator.getEpochCommitment(labelToBytes32("epoch:missing")),
    ).toThrow(/not registered/i);

    expect(() =>
      pureCircuits.createEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        10n,
        9n,
      ),
    ).toThrow(/later than valid from/i);

    const createPayloadHash = computeCreateEpochCommitmentPayloadHash(
      epoch.epochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      epoch.validFromSequence,
      epoch.validUntilSequence,
    );
    const tamperedSignature = {
      ...signPolicyBoundMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        simulator.getLedger().governancePolicyCommitment,
        CREATE_EPOCH_ACTION_KIND,
        createPayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };

    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);

    const uncommittedPolicyRoot = labelToBytes32("policy-root:uncommitted");
    const uncommittedSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        uncommittedPolicyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        uncommittedSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        uncommittedPolicyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
    ).toThrow(/committed governance policy/i);

    const futureFrom = simulator.getLedger().governanceActionCount + 1n;
    const futureSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        futureFrom,
        futureFrom + 60n,
      ),
      simulator.getLedger().governanceActionCount,
    );
    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        futureSignature,
        epoch.epochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        futureFrom,
        futureFrom + 60n,
      ),
    ).toThrow(/cannot start after its publication action/i);

    const signature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      createPayloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      epoch.epochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      epoch.validFromSequence,
      epoch.validUntilSequence,
    );

    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signPolicyBoundMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          simulator.getLedger().governancePolicyCommitment,
          CREATE_EPOCH_ACTION_KIND,
          computeCreateEpochCommitmentPayloadHash(
            epoch.epochId,
            labelToBytes32("state-root:duplicate"),
            epoch.eventRoot,
            epoch.policyRoot,
            epoch.validFromSequence,
            epoch.validUntilSequence,
          ),
          simulator.getLedger().governanceActionCount,
        ),
        epoch.epochId,
        labelToBytes32("state-root:duplicate"),
        epoch.eventRoot,
        epoch.policyRoot,
        epoch.validFromSequence,
        epoch.validUntilSequence,
      ),
    ).toThrow(/already exists/i);

    const revisionSequence = simulator.getLedger().governanceActionCount;
    const revisedPolicyRoot = labelToBytes32("policy:kanon:v2");
    const revisionSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        epoch.policyRoot,
        revisedPolicyRoot,
        2n,
        1n,
        1n,
        1n,
      ),
      revisionSequence,
    );
    simulator.updateMaintainerThresholdPolicy(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      revisionSignature,
      revisedPolicyRoot,
      2n,
      1n,
      1n,
      1n,
    );
    expect(Buffer.from(simulator.getLedger().lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(epoch.policyRoot),
    );
    const revisionEventHash = simulator.getLedger().lastGovernanceEventHash;
    expect(Buffer.from(revisionEventHash)).toEqual(Buffer.from(pureCircuits.governanceEventHash(
      registryId,
      epoch.policyRoot,
      simulator.getLedger().lastAuthorizedSignerSetHash,
      UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND,
      computeUpdateMaintainerThresholdPolicyPayloadHash(
        epoch.policyRoot,
        revisedPolicyRoot,
        2n,
        1n,
        1n,
        1n,
      ),
      revisionSequence,
    )));

    const historicalEpochId = labelToBytes32("epoch:historical-old-policy");
    const historicalFrom = epoch.validFromSequence;
    const historicalUntil = epoch.validUntilSequence;
    const historicalSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        historicalEpochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        historicalFrom,
        historicalUntil,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.publishEpochCommitment(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      historicalSignature,
      historicalEpochId,
      epoch.stateRoot,
      epoch.eventRoot,
      epoch.policyRoot,
      historicalFrom,
      historicalUntil,
    );
    const historicalRecord = simulator.getEpochCommitment(historicalEpochId);
    expect(Buffer.from(historicalRecord.policyRoot)).toEqual(Buffer.from(epoch.policyRoot));
    expect(Buffer.from(historicalRecord.publicationPolicyCommitment)).toEqual(
      Buffer.from(revisedPolicyRoot),
    );
    expect(Buffer.from(simulator.getLedger().lastAuthorizedPolicyCommitment)).toEqual(
      Buffer.from(revisedPolicyRoot),
    );
    expect(simulator.getLedger().governanceEventHashes.member(revisionEventHash)).toBe(true);

    const lateSequence = simulator.getLedger().governanceActionCount;
    const lateEpochId = labelToBytes32("epoch:late-old-policy");
    const lateSignature = signPolicyBoundMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      CREATE_EPOCH_ACTION_KIND,
      computeCreateEpochCommitmentPayloadHash(
        lateEpochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        lateSequence,
        lateSequence + 60n,
      ),
      lateSequence,
    );
    expect(() =>
      simulator.publishEpochCommitment(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        lateSignature,
        lateEpochId,
        epoch.stateRoot,
        epoch.eventRoot,
        epoch.policyRoot,
        lateSequence,
        lateSequence + 60n,
      ),
    ).toThrow(/superseded at this sequence/i);
  });
});
