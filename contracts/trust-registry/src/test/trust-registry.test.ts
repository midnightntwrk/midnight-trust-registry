import { Buffer } from "node:buffer";

import {
  computeCreateIssuerAuthorizationPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
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
const SUSPEND_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:suspend");
const REVOKE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:revoke");
const ARCHIVE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:archive");

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

    const createSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      CREATE_ISSUER_ACTION_KIND,
      createPayloadHash,
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

    expect(() =>
      simulator.createIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          CREATE_ISSUER_ACTION_KIND,
          computeCreateIssuerAuthorizationPayloadHash(
            labelToBytes32("issuer-auth:license:duplicate"),
            issuerAuthorization.subjectDidCommitment,
            issuerAuthorization.resourceType,
            issuerAuthorization.resourceId,
            issuerAuthorization.policyId,
            issuerAuthorization.trustLevel,
            labelToBytes32("evidence:license:duplicate"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        labelToBytes32("issuer-auth:license:duplicate"),
        issuerAuthorization.subjectDidCommitment,
        issuerAuthorization.resourceType,
        issuerAuthorization.resourceId,
        issuerAuthorization.policyId,
        issuerAuthorization.trustLevel,
        labelToBytes32("evidence:license:duplicate"),
      ),
    ).toThrow(/live authorization/i);

    const createdRecord = simulator.getIssuerAuthorization(
      issuerAuthorization.authorizationId,
    );
    const archiveEvidenceHash = labelToBytes32("evidence:license:archive");
    const archiveSignature = signMaintainerActionFromSeed(
      bootstrapMaintainer.seed,
      registryId,
      ARCHIVE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        issuerAuthorization.authorizationId,
        createdRecord.lifecycleEventHash,
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

    expect(() =>
      simulator.revokeIssuerAuthorization(
        bootstrapMaintainer.keyId,
        bootstrapPublicKey,
        signMaintainerActionFromSeed(
          bootstrapMaintainer.seed,
          registryId,
          REVOKE_ISSUER_ACTION_KIND,
          computeUpdateIssuerAuthorizationPayloadHash(
            issuerAuthorization.authorizationId,
            simulator.getIssuerAuthorization(issuerAuthorization.authorizationId)
              .lifecycleEventHash,
            labelToBytes32("evidence:license:revoke"),
          ),
          simulator.getLedger().governanceActionCount,
        ),
        issuerAuthorization.authorizationId,
        labelToBytes32("evidence:license:revoke"),
      ),
    ).toThrow(/active or suspended/i);
  });
});
