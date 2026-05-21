import { Buffer } from "node:buffer";

import {
  computeCreateAuditorAuthorizationPayloadHash,
  computeCreateEpochCommitmentPayloadHash,
  computeCreateRecognitionPayloadHash,
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeUpdateAuditorAuthorizationPayloadHash,
  computeUpdateRecognitionPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
  computeUpdateVerifierAuthorizationPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  signMaintainerActionFromSeed,
  verifyMaintainerAction,
} from "../signing.js";
import {
  createMaintainerFixture,
  labelToBytes32,
  TrustRegistrySimulator,
} from "../testing.js";
import {
  AuthorizationStatus,
  IssuerResourceType,
  MaintainerStatus,
  pureCircuits,
} from "../managed/trust-registry/contract/index.js";

import { describe, expect, it } from "vitest";

const CREATE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:create");
const PROPOSE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:propose");
const AUTHORIZE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:authorize");
const ACTIVATE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:activate");
const SUSPEND_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:suspend");
const REVOKE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:revoke");
const ARCHIVE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:archive");
const CREATE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:create");
const PROPOSE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:propose");
const AUTHORIZE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:authorize");
const ACTIVATE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:activate");
const SUSPEND_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:suspend");
const REVOKE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:revoke");
const ARCHIVE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:archive");
const CREATE_RECOGNITION_ACTION_KIND = labelToBytes32("tr:recognition:create");
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

const createEpochCommitmentFixture = (label: string) => ({
  epochId: labelToBytes32(`epoch:${label}`),
  stateRoot: labelToBytes32(`state-root:${label}`),
  eventRoot: labelToBytes32(`event-root:${label}`),
  policyRoot: labelToBytes32(`policy-root:${label}`),
  validFromSequence: 1n,
  validUntilSequence: 61n,
});

describe("trust registry contract", () => {
  it("accepts valid threshold rules and rejects invalid ones", () => {
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 2n)).not.toThrow();
    expect(() => pureCircuits.assertValidMaintainerThreshold(0n, 1n)).toThrow(
      /at least 1/i,
    );
    expect(() => pureCircuits.assertValidMaintainerThreshold(3n, 4n)).toThrow(
      /may not exceed/i,
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
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const state = simulator.getLedger();
    const maintainer = state.maintainerRecords.lookup(bootstrapMaintainer.keyId);

    expect(state.initialized).toBe(true);
    expect(Buffer.from(state.registryId)).toEqual(Buffer.from(registryId));
    expect(Buffer.from(state.registryDidCommitment)).toEqual(
      Buffer.from(registryDidCommitment),
    );
    expect(Buffer.from(state.governancePolicyCommitment)).toEqual(
      Buffer.from(governancePolicyCommitment),
    );
    expect(state.maintainerThreshold).toEqual(1n);
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
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        2n,
      ),
    ).toThrow(/may not exceed active maintainer count/i);

    simulator.initializeRegistry(
      labelToBytes32("registry:kanon"),
      labelToBytes32("did:midnight:registry"),
      labelToBytes32("policy:kanon:v1"),
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    expect(() =>
      simulator.initializeRegistry(
        labelToBytes32("registry:kanon:second"),
        labelToBytes32("did:midnight:registry:second"),
        labelToBytes32("policy:kanon:v2"),
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        1n,
      ),
    ).toThrow(/already been initialized/i);
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
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const actionKind = labelToBytes32("tr:authorize:issuer");
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );

    expect(
      verifyMaintainerAction(
        bootstrapPublicKey,
        registryId,
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

  it("rejects maintainer actions before initialization and rejects tampered authorization", () => {
    const simulator = new TrustRegistrySimulator();
    const registryId = labelToBytes32("registry:kanon");
    const actionKind = labelToBytes32("tr:authorize:issuer");
    const actionPayloadHash = labelToBytes32("issuer:example:v1");
    const bootstrapMaintainer = createMaintainerFixture("bootstrap", 5);
    const bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
      bootstrapMaintainer.seed,
    );
    const signatureBeforeInit = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      1n,
    );

    const actionSequence = simulator.getLedger().governanceActionCount;
    const validSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(17);
    const issuerAuthorization = createIssuerAuthorizationFixture("birth");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.trustLevel,
        issuerAuthorization.evidenceHash,
      ),
      actionSequence,
    );

    const eventHash = simulator.createIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      issuerAuthorization.authorizationId,
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
      issuerAuthorization.policyId,
      issuerAuthorization.trustLevel,
      issuerAuthorization.evidenceHash,
    );
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
    const proposalSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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

    const authorizationEvidenceHash = labelToBytes32(
      "evidence:application:authorize",
    );
    const authorizationSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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

    const activationEvidenceHash = labelToBytes32("evidence:application:active");
    const activationSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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

    const archivedProposalSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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

    const revocableProposalSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const authorizeEvidenceHash = labelToBytes32("evidence:revocable:authorize");
    const authorizeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const revokeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(23);
    const issuerAuthorization = createIssuerAuthorizationFixture("degree");

    const createSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.trustLevel,
        issuerAuthorization.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.createIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      createSignature,
      issuerAuthorization.authorizationId,
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
      issuerAuthorization.policyId,
      issuerAuthorization.trustLevel,
      issuerAuthorization.evidenceHash,
    );

    const createdRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    const suspendEvidenceHash = labelToBytes32("evidence:degree:suspend");
    const suspendSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const revokeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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

  it("rejects duplicate issuer scope creation, invalid transitions, tampered signatures, and missing queries", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(29);
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

    const createPayloadHash = computeCreateIssuerAuthorizationPayloadHash(
      issuerAuthorization.authorizationId,
      issuerAuthorization.subjectDidCommitment,
      issuerAuthorization.resourceType,
      issuerAuthorization.resourceId,
      issuerAuthorization.policyId,
      issuerAuthorization.trustLevel,
      issuerAuthorization.evidenceHash,
    );
    const tamperedCreateSignature = {
      ...signMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        CREATE_ISSUER_ACTION_KIND,
        createPayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };

    expect(() =>
      simulator.createIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedCreateSignature,
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
    const proposalSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
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
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
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

    const directIssuerAuthorization =
      createIssuerAuthorizationFixture("license-direct");
    const createSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        directIssuerAuthorization.authorizationId,
        directIssuerAuthorization.subjectDidCommitment,
        directIssuerAuthorization.resourceType,
        directIssuerAuthorization.resourceId,
        directIssuerAuthorization.policyId,
        directIssuerAuthorization.trustLevel,
        directIssuerAuthorization.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.createIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      createSignature,
      directIssuerAuthorization.authorizationId,
      directIssuerAuthorization.subjectDidCommitment,
      directIssuerAuthorization.resourceType,
      directIssuerAuthorization.resourceId,
      directIssuerAuthorization.policyId,
      directIssuerAuthorization.trustLevel,
      directIssuerAuthorization.evidenceHash,
    );

    expect(() =>
      simulator.createIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          CREATE_ISSUER_ACTION_KIND,
          computeCreateIssuerAuthorizationPayloadHash(
            labelToBytes32("issuer-auth:license-direct:duplicate"),
            directIssuerAuthorization.subjectDidCommitment,
            directIssuerAuthorization.resourceType,
            directIssuerAuthorization.resourceId,
            directIssuerAuthorization.policyId,
            directIssuerAuthorization.trustLevel,
            labelToBytes32("evidence:license-direct:duplicate"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        labelToBytes32("issuer-auth:license-direct:duplicate"),
        directIssuerAuthorization.subjectDidCommitment,
        directIssuerAuthorization.resourceType,
        directIssuerAuthorization.resourceId,
        directIssuerAuthorization.policyId,
        directIssuerAuthorization.trustLevel,
        labelToBytes32("evidence:license-direct:duplicate"),
      ),
    ).toThrow(/live authorization/i);

    expect(() =>
      simulator.authorizeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          AUTHORIZE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            directIssuerAuthorization.authorizationId,
            simulator.getIssuerAuthorization(
              directIssuerAuthorization.authorizationId,
            ).lifecycleEventHash,
            labelToBytes32("evidence:license-direct:authorize"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        directIssuerAuthorization.authorizationId,
        labelToBytes32("evidence:license-direct:authorize"),
      ),
    ).toThrow(/must be proposed/i);

    const createdRecord = simulator.getIssuerAuthorization(
      directIssuerAuthorization.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:license:archive");
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        directIssuerAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
        archiveEvidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.archiveIssuerAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      archiveSignature,
      directIssuerAuthorization.authorizationId,
      archiveEvidenceHash,
    );

    expect(() =>
      simulator.revokeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          REVOKE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            directIssuerAuthorization.authorizationId,
            simulator.getIssuerAuthorization(
              directIssuerAuthorization.authorizationId,
            ).lifecycleEventHash,
            labelToBytes32("evidence:license:revoke"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        directIssuerAuthorization.authorizationId,
        labelToBytes32("evidence:license:revoke"),
      ),
    ).toThrow(/authorized, active, or suspended/i);
  });

  it("creates and queries an active verifier authorization with predicate and disclosure scoped lookups", () => {
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(31);
    const verifierAuthorization = createVerifierAuthorizationFixture("age-gate");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_VERIFIER_ACTION_KIND,
      computeCreateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
        verifierAuthorization.policyId,
        verifierAuthorization.trustLevel,
        verifierAuthorization.evidenceHash,
      ),
      actionSequence,
    );

    const eventHash = simulator.createVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
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

    const proposeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
        labelToBytes32("evidence:employment-application:propose"),
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
      labelToBytes32("evidence:employment-application:propose"),
    );

    const proposedRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);

    const authorizeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      AUTHORIZE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        labelToBytes32("evidence:employment-application:authorize"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      verifierAuthorization.authorizationId,
      labelToBytes32("evidence:employment-application:authorize"),
    );

    const authorizedRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(simulator.getLedger().activeVerifierAuthorizationCount).toEqual(0n);

    const activateSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      ACTIVATE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        labelToBytes32("evidence:employment-application:activate"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      verifierAuthorization.authorizationId,
      labelToBytes32("evidence:employment-application:activate"),
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
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(37);
    const verifierAuthorization = createVerifierAuthorizationFixture("university");

    const createSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_VERIFIER_ACTION_KIND,
      computeCreateVerifierAuthorizationPayloadHash(
        verifierAuthorization.authorizationId,
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
        verifierAuthorization.policyId,
        verifierAuthorization.trustLevel,
        verifierAuthorization.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.createVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      createSignature,
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

    const createdRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const suspendEvidenceHash = labelToBytes32("evidence:university:suspend");
    const suspendSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const revokeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(41);
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

    const createPayloadHash = computeCreateVerifierAuthorizationPayloadHash(
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
    const tamperedCreateSignature = {
      ...signMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        CREATE_VERIFIER_ACTION_KIND,
        createPayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };

    expect(() =>
      simulator.createVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedCreateSignature,
        verifierAuthorization.authorizationId,
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
        verifierAuthorization.policyId,
        verifierAuthorization.trustLevel,
        verifierAuthorization.evidenceHash,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);

    const createSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_VERIFIER_ACTION_KIND,
      createPayloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.createVerifierAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      createSignature,
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

    expect(() =>
      simulator.createVerifierAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          CREATE_VERIFIER_ACTION_KIND,
          computeCreateVerifierAuthorizationPayloadHash(
            labelToBytes32("verifier-auth:passport:duplicate"),
            verifierAuthorization.subjectDidCommitment,
            verifierAuthorization.requestProfileId,
            verifierAuthorization.allowedAttributeSetCommitment,
            verifierAuthorization.allowedPredicateSetCommitment,
            verifierAuthorization.disclosureLevelCommitment,
            verifierAuthorization.policyId,
            verifierAuthorization.trustLevel,
            labelToBytes32("evidence:passport:duplicate"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        labelToBytes32("verifier-auth:passport:duplicate"),
        verifierAuthorization.subjectDidCommitment,
        verifierAuthorization.requestProfileId,
        verifierAuthorization.allowedAttributeSetCommitment,
        verifierAuthorization.allowedPredicateSetCommitment,
        verifierAuthorization.disclosureLevelCommitment,
        verifierAuthorization.policyId,
        verifierAuthorization.trustLevel,
        labelToBytes32("evidence:passport:duplicate"),
      ),
    ).toThrow(/live authorization/i);

    const createdRecord = simulator.getVerifierAuthorization(
      verifierAuthorization.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:passport:archive");
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
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
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(43);
    const recognition = createRecognitionFixture("gaia-x");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_RECOGNITION_ACTION_KIND,
      computeCreateRecognitionPayloadHash(
        recognition.recognitionId,
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
        recognition.policyId,
        recognition.trustLevel,
        recognition.evidenceHash,
      ),
      actionSequence,
    );

    const eventHash = simulator.createRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      signature,
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    );
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

    const proposeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      PROPOSE_RECOGNITION_ACTION_KIND,
      computeCreateRecognitionPayloadHash(
        recognition.recognitionId,
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
        recognition.policyId,
        recognition.trustLevel,
        labelToBytes32("evidence:gaia-x-application:propose"),
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
      labelToBytes32("evidence:gaia-x-application:propose"),
    );

    const proposedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(proposedRecord.status).toEqual(AuthorizationStatus.proposed);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);

    const authorizeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      AUTHORIZE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        proposedRecord.lifecycleEventHash,
        labelToBytes32("evidence:gaia-x-application:authorize"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      recognition.recognitionId,
      labelToBytes32("evidence:gaia-x-application:authorize"),
    );

    const authorizedRecord = simulator.getRecognition(recognition.recognitionId);
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);
    expect(simulator.getLedger().activeRecognitionCount).toEqual(0n);

    const activateSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      ACTIVATE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        recognition.recognitionId,
        authorizedRecord.lifecycleEventHash,
        labelToBytes32("evidence:gaia-x-application:activate"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      recognition.recognitionId,
      labelToBytes32("evidence:gaia-x-application:activate"),
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
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(47);
    const recognition = createRecognitionFixture("eidas");

    const createSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_RECOGNITION_ACTION_KIND,
      computeCreateRecognitionPayloadHash(
        recognition.recognitionId,
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
        recognition.policyId,
        recognition.trustLevel,
        recognition.evidenceHash,
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.createRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      createSignature,
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    );

    const createdRecord = simulator.getRecognition(recognition.recognitionId);
    const suspendEvidenceHash = labelToBytes32("evidence:eidas:suspend");
    const suspendSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const revokeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const {
      simulator,
      registryId,
      bootstrapMaintainer,
      bootstrapPublicKey,
    } = createInitializedRegistryFixture(53);
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

    const createPayloadHash = computeCreateRecognitionPayloadHash(
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    );
    const tamperedCreateSignature = {
      ...signMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
        CREATE_RECOGNITION_ACTION_KIND,
        createPayloadHash,
        simulator.getLedger().governanceActionCount,
      ),
      response: 0n,
    };

    expect(() =>
      simulator.createRecognition(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        tamperedCreateSignature,
        recognition.recognitionId,
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
        recognition.policyId,
        recognition.trustLevel,
        recognition.evidenceHash,
      ),
    ).toThrow(/invalid jubjub schnorr signature/i);

    const createSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_RECOGNITION_ACTION_KIND,
      createPayloadHash,
      simulator.getLedger().governanceActionCount,
    );
    simulator.createRecognition(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      createSignature,
      recognition.recognitionId,
      recognition.recognizedAuthorityDidCommitment,
      recognition.recognizedRegistryId,
      recognition.scopeResourceType,
      recognition.scopeResourceId,
      recognition.policyId,
      recognition.trustLevel,
      recognition.evidenceHash,
    );

    expect(() =>
      simulator.createRecognition(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          CREATE_RECOGNITION_ACTION_KIND,
          computeCreateRecognitionPayloadHash(
            labelToBytes32("recognition:gaia-net:duplicate"),
            recognition.recognizedAuthorityDidCommitment,
            recognition.recognizedRegistryId,
            recognition.scopeResourceType,
            recognition.scopeResourceId,
            recognition.policyId,
            recognition.trustLevel,
            labelToBytes32("evidence:gaia-net:duplicate"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        labelToBytes32("recognition:gaia-net:duplicate"),
        recognition.recognizedAuthorityDidCommitment,
        recognition.recognizedRegistryId,
        recognition.scopeResourceType,
        recognition.scopeResourceId,
        recognition.policyId,
        recognition.trustLevel,
        labelToBytes32("evidence:gaia-net:duplicate"),
      ),
    ).toThrow(/live recognition/i);

    const createdRecord = simulator.getRecognition(recognition.recognitionId);
    const archiveEvidenceHash = labelToBytes32("evidence:gaia-net:archive");
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
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

    const proposeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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

    const authorizeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      AUTHORIZE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        proposedRecord.lifecycleEventHash,
        labelToBytes32("evidence:iso-27001:authorize"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.authorizeAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      authorizeSignature,
      auditorAuthorization.authorizationId,
      labelToBytes32("evidence:iso-27001:authorize"),
    );

    const authorizedRecord = simulator.getAuditorAuthorization(
      auditorAuthorization.authorizationId,
    );
    expect(authorizedRecord.status).toEqual(AuthorizationStatus.authorized);

    const activateSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      ACTIVATE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        auditorAuthorization.authorizationId,
        authorizedRecord.lifecycleEventHash,
        labelToBytes32("evidence:iso-27001:activate"),
      ),
      simulator.getLedger().governanceActionCount,
    );
    simulator.activateAuditorAuthorization(
      bootstrapMaintainer.keyId,
      bootstrapPublicKey,
      activateSignature,
      auditorAuthorization.authorizationId,
      labelToBytes32("evidence:iso-27001:activate"),
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

    const revokeSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const epoch = createEpochCommitmentFixture("seq-1");
    const actionSequence = simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
    const epoch = createEpochCommitmentFixture("seq-2");

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
      ...signMaintainerActionFromSeed(
        bootstrapMaintainer.seed,
        registryId,
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

    const signature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
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
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
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
  });
});
