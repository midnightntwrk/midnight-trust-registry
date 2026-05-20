import { Buffer } from "node:buffer";

import {
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
  computeUpdateVerifierAuthorizationPayloadHash,
  createMaintainerFixture,
  deriveJubjubPublicKeyFromSeed,
  labelToBytes32,
  signMaintainerActionFromSeed,
  TrustRegistrySimulator,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  AuthorizationStatus as ContractAuthorizationStatus,
  IssuerResourceType,
  type IssuerAuthorizationRecord as ContractIssuerAuthorizationRecord,
  type VerifierAuthorizationRecord as ContractVerifierAuthorizationRecord,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  AuthorizationRecordSchema,
  GovernancePolicyRecordSchema,
  type RegistryRecord,
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
  type AuthorizationRecord,
  type GovernancePolicyRecord,
  type TrustRegistryEvidenceBundle,
  createScopedIdentifier,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  bytes32Commitment,
  createMidnightDid,
  type IssuerScenarioFixture,
  type VerifierScenarioFixture,
} from "./fixtures.js";

const CREATE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:create");
const SUSPEND_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:suspend");
const REVOKE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:revoke");
const ARCHIVE_ISSUER_ACTION_KIND = labelToBytes32("tr:issuer:archive");
const CREATE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:create");
const SUSPEND_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:suspend");
const REVOKE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:revoke");
const ARCHIVE_VERIFIER_ACTION_KIND = labelToBytes32("tr:verifier:archive");

const BASE_TIMESTAMP_MS = Date.parse("2026-05-20T00:00:00Z");

const bytes32Hex = (value: Uint8Array): string =>
  `0x${Buffer.from(value).toString("hex")}`;

const timestampForSequence = (sequence: bigint): string =>
  new Date(BASE_TIMESTAMP_MS + Number(sequence) * 60_000).toISOString();

const optionalSequenceTimestamp = (
  sequence: bigint,
  fieldName: string,
): Partial<Record<string, string>> =>
  sequence > 0n ? { [fieldName]: timestampForSequence(sequence) } : {};

const issuerResourceTypeName = (
  resourceType: IssuerResourceType,
): AuthorizationRecord["resourceType"] => {
  switch (resourceType) {
    case IssuerResourceType.credentialFamily:
      return "credential-family";
    case IssuerResourceType.schema:
      return "schema";
    case IssuerResourceType.schemaVersion:
      return "schema-version";
    case IssuerResourceType.credentialDefinition:
      return "credential-definition";
    case IssuerResourceType.statusMethodRequirement:
      return "status-method-requirement";
  }
};

const contractStatusName = (
  status: ContractAuthorizationStatus,
): AuthorizationRecord["status"] => {
  switch (status) {
    case ContractAuthorizationStatus.active:
      return "active";
    case ContractAuthorizationStatus.suspended:
      return "suspended";
    case ContractAuthorizationStatus.revoked:
      return "revoked";
    case ContractAuthorizationStatus.archived:
      return "archived";
  }
};

const bundleLeafHash = (authorization: AuthorizationRecord): string =>
  sha256Hex(
    JSON.stringify({
      authorizationId: authorization.authorizationId,
      status: authorization.status,
      subjectDid: authorization.subjectDid,
      resourceId: authorization.resourceId,
    }),
  );

export class LocalTrustRegistryIntegrationHarness {
  readonly simulator: TrustRegistrySimulator;
  readonly registryId: string;
  readonly registryDid: string;
  readonly registryIdCommitment: Uint8Array;
  readonly registryDidCommitment: Uint8Array;
  readonly policyId: string;
  readonly governancePolicyCommitment: Uint8Array;
  readonly registryRecord: RegistryRecord;
  readonly policyRecord: GovernancePolicyRecord;
  readonly maintainerDid: string;

  private readonly bootstrapMaintainer = createMaintainerFixture("bootstrap", 17);
  private readonly bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
    this.bootstrapMaintainer.seed,
  );

  constructor(label = "kanon") {
    this.simulator = new TrustRegistrySimulator();
    this.registryId = createScopedIdentifier("registry", label, "trusted");
    this.registryDid = createMidnightDid(`registry:${label}`);
    this.registryIdCommitment = bytes32Commitment(this.registryId);
    this.registryDidCommitment = bytes32Commitment(this.registryDid);
    this.policyId = createScopedIdentifier("policy", label, "v1");
    this.governancePolicyCommitment = bytes32Commitment(this.policyId);
    this.maintainerDid = createMidnightDid(`maintainer:${label}:bootstrap`);
    this.registryRecord = RegistryRecordSchema.parse({
      registryId: this.registryId,
      registryDid: this.registryDid,
      name: "Kanon Trusted Registry",
      description: "Simulator-first trust registry integration environment",
      controllerDids: [this.maintainerDid],
      maintainerDids: [this.maintainerDid],
      policyUri: "https://registry.example/policies/kanon-v1",
      serviceEndpoint: "https://registry.example/query",
      logoUri: "https://registry.example/logo.svg",
      status: "active",
      createdAt: timestampForSequence(0n),
      updatedAt: timestampForSequence(0n),
      lifecycleEventRoot: sha256Hex(this.registryId),
    });
    this.policyRecord = GovernancePolicyRecordSchema.parse({
      policyId: this.policyId,
      registryId: this.registryId,
      version: "v1",
      policyUri: "https://registry.example/policies/kanon-v1",
      status: "active",
      effectiveFrom: timestampForSequence(0n),
      decisionRules: ["single bootstrap maintainer approval in simulator mode"],
      disputeRules: ["manual operator review"],
      retentionRules: ["retain historical trust evidence for long-term verification"],
      emergencyRules: ["maintainer may suspend compromised participants immediately"],
      lifecycleEventRoot: sha256Hex(this.policyId),
    });

    this.simulator.initializeRegistry(
      this.registryIdCommitment,
      this.registryDidCommitment,
      this.governancePolicyCommitment,
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      1n,
    );
  }

  authorizeIssuer(fixture: IssuerScenarioFixture): Uint8Array {
    const evidenceHash = bytes32Commitment(`${fixture.authorizationId}:create`);
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      CREATE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        fixture.subjectDidCommitment,
        fixture.resourceType,
        fixture.resourceIdCommitment,
        this.governancePolicyCommitment,
        bytes32Commitment(fixture.trustLevel),
        evidenceHash,
      ),
      actionSequence,
    );

    return this.simulator.createIssuerAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.resourceType,
      fixture.resourceIdCommitment,
      this.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      evidenceHash,
    );
  }

  suspendIssuer(fixture: IssuerScenarioFixture): Uint8Array {
    return this.updateIssuerLifecycle(
      fixture,
      "suspend",
      SUSPEND_ISSUER_ACTION_KIND,
    );
  }

  revokeIssuer(fixture: IssuerScenarioFixture): Uint8Array {
    return this.updateIssuerLifecycle(
      fixture,
      "revoke",
      REVOKE_ISSUER_ACTION_KIND,
    );
  }

  archiveIssuer(fixture: IssuerScenarioFixture): Uint8Array {
    return this.updateIssuerLifecycle(
      fixture,
      "archive",
      ARCHIVE_ISSUER_ACTION_KIND,
    );
  }

  authorizeVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    const evidenceHash = bytes32Commitment(`${fixture.authorizationId}:create`);
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      CREATE_VERIFIER_ACTION_KIND,
      computeCreateVerifierAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        fixture.subjectDidCommitment,
        fixture.requestProfileIdCommitment,
        fixture.allowedAttributeSetCommitment,
        fixture.allowedPredicateSetCommitment,
        fixture.disclosureLevelCommitment,
        this.governancePolicyCommitment,
        bytes32Commitment(fixture.trustLevel),
        evidenceHash,
      ),
      actionSequence,
    );

    return this.simulator.createVerifierAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.requestProfileIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
      this.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      evidenceHash,
    );
  }

  suspendVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    return this.updateVerifierLifecycle(
      fixture,
      "suspend",
      SUSPEND_VERIFIER_ACTION_KIND,
    );
  }

  revokeVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    return this.updateVerifierLifecycle(
      fixture,
      "revoke",
      REVOKE_VERIFIER_ACTION_KIND,
    );
  }

  archiveVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    return this.updateVerifierLifecycle(
      fixture,
      "archive",
      ARCHIVE_VERIFIER_ACTION_KIND,
    );
  }

  evaluateCurrentIssuerDecision(
    fixture: IssuerScenarioFixture,
    options: { expectedRegistryId?: string } = {},
  ): TrustRegistryEvidenceBundle {
    this.assertRegistryId(options.expectedRegistryId);
    this.simulator.assertIssuerAuthorized(
      fixture.subjectDidCommitment,
      fixture.resourceType,
      fixture.resourceIdCommitment,
    );
    return this.buildIssuerHistoricalEvidence(fixture);
  }

  buildIssuerHistoricalEvidence(
    fixture: IssuerScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    const record = this.simulator.getIssuerAuthorization(
      fixture.authorizationIdCommitment,
    );
    const authorization = this.buildIssuerAuthorizationRecord(fixture, record);
    return this.buildEvidenceBundle(
      authorization,
      fixture.subjectDid,
      fixture.referencedStatusRegistryId,
      record.lastStatusSequence,
    );
  }

  evaluateCurrentVerifierDecision(
    fixture: VerifierScenarioFixture,
    options: { expectedRegistryId?: string } = {},
  ): TrustRegistryEvidenceBundle {
    this.assertRegistryId(options.expectedRegistryId);
    this.simulator.assertVerifierAuthorized(
      fixture.subjectDidCommitment,
      fixture.requestProfileIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
    );
    return this.buildVerifierHistoricalEvidence(fixture);
  }

  buildVerifierHistoricalEvidence(
    fixture: VerifierScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    const record = this.simulator.getVerifierAuthorization(
      fixture.authorizationIdCommitment,
    );
    const authorization = this.buildVerifierAuthorizationRecord(fixture, record);
    return this.buildEvidenceBundle(
      authorization,
      fixture.subjectDid,
      fixture.referencedStatusRegistryId,
      record.lastStatusSequence,
    );
  }

  private updateIssuerLifecycle(
    fixture: IssuerScenarioFixture,
    actionName: "suspend" | "revoke" | "archive",
    actionKind: Uint8Array,
  ): Uint8Array {
    const evidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:${actionName}`,
    );
    const currentRecord = this.simulator.getIssuerAuthorization(
      fixture.authorizationIdCommitment,
    );
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      actionKind,
      computeUpdateIssuerAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        currentRecord.lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    if (actionName === "suspend") {
      return this.simulator.suspendIssuerAuthorization(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.authorizationIdCommitment,
        evidenceHash,
      );
    }
    if (actionName === "revoke") {
      return this.simulator.revokeIssuerAuthorization(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.authorizationIdCommitment,
        evidenceHash,
      );
    }
    return this.simulator.archiveIssuerAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
      evidenceHash,
    );
  }

  private updateVerifierLifecycle(
    fixture: VerifierScenarioFixture,
    actionName: "suspend" | "revoke" | "archive",
    actionKind: Uint8Array,
  ): Uint8Array {
    const evidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:${actionName}`,
    );
    const currentRecord = this.simulator.getVerifierAuthorization(
      fixture.authorizationIdCommitment,
    );
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      actionKind,
      computeUpdateVerifierAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        currentRecord.lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    if (actionName === "suspend") {
      return this.simulator.suspendVerifierAuthorization(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.authorizationIdCommitment,
        evidenceHash,
      );
    }
    if (actionName === "revoke") {
      return this.simulator.revokeVerifierAuthorization(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.authorizationIdCommitment,
        evidenceHash,
      );
    }
    return this.simulator.archiveVerifierAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
      evidenceHash,
    );
  }

  private assertRegistryId(expectedRegistryId?: string): void {
    if (expectedRegistryId !== undefined && expectedRegistryId !== this.registryId) {
      throw new Error(
        `Trust registry mismatch: expected ${expectedRegistryId}, got ${this.registryId}`,
      );
    }
  }

  private buildIssuerAuthorizationRecord(
    fixture: IssuerScenarioFixture,
    record: ContractIssuerAuthorizationRecord,
  ): AuthorizationRecord {
    return this.buildAuthorizationRecord({
      authorizationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      role: "issuer",
      resourceType: issuerResourceTypeName(fixture.resourceType),
      resourceId: fixture.resourceId,
      trustLevel: fixture.trustLevel,
      record,
    });
  }

  private buildVerifierAuthorizationRecord(
    fixture: VerifierScenarioFixture,
    record: ContractVerifierAuthorizationRecord,
  ): AuthorizationRecord {
    return this.buildAuthorizationRecord({
      authorizationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      role: "verifier",
      resourceType: "request-profile",
      resourceId: fixture.scopeResourceId,
      trustLevel: fixture.trustLevel,
      record,
    });
  }

  private buildAuthorizationRecord(input: {
    authorizationId: string;
    subjectDid: string;
    role: AuthorizationRecord["role"];
    resourceType: AuthorizationRecord["resourceType"];
    resourceId: string;
    trustLevel: string;
    record:
      | ContractIssuerAuthorizationRecord
      | ContractVerifierAuthorizationRecord;
  }): AuthorizationRecord {
    const { record } = input;
    const status = contractStatusName(record.status);

    return AuthorizationRecordSchema.parse({
      authorizationId: input.authorizationId,
      registryId: this.registryId,
      subjectDid: input.subjectDid,
      role: input.role,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      policyId: this.policyId,
      trustLevel: input.trustLevel,
      status,
      proposedAt: timestampForSequence(record.proposedAtSequence),
      ...(record.authorizedAtSequence > 0n
        ? { authorizedAt: timestampForSequence(record.authorizedAtSequence) }
        : {}),
      ...(record.activeFromSequence > 0n
        ? { activeFrom: timestampForSequence(record.activeFromSequence) }
        : {}),
      ...optionalSequenceTimestamp(record.suspendedAtSequence, "suspendedAt"),
      ...optionalSequenceTimestamp(record.revokedAtSequence, "revokedAt"),
      ...optionalSequenceTimestamp(record.archivedAtSequence, "archivedAt"),
      evidenceHash: bytes32Hex(record.evidenceHash),
      lifecycleEventRoot: bytes32Hex(record.lifecycleEventHash),
    });
  }

  private buildEvidenceBundle(
    authorization: AuthorizationRecord,
    subjectDid: string,
    referencedStatusRegistryId: string,
    lastStatusSequence: bigint,
  ): TrustRegistryEvidenceBundle {
    const epochId = createScopedIdentifier(
      "epoch",
      this.registryId,
      `seq-${lastStatusSequence.toString()}`,
    );
    const epochValidFrom = timestampForSequence(lastStatusSequence);
    const epochValidUntil = new Date(
      Date.parse(epochValidFrom) + 60 * 60 * 1000,
    ).toISOString();
    const stateRoot = sha256Hex(
      JSON.stringify({
        registryId: this.registryId,
        authorizationId: authorization.authorizationId,
        status: authorization.status,
        lifecycleEventRoot: authorization.lifecycleEventRoot,
      }),
    );
    const eventRoot = authorization.lifecycleEventRoot;
    const policyRoot = sha256Hex(this.policyId);

    return TrustRegistryEvidenceBundleSchema.parse({
      bundleId: createScopedIdentifier(
        "bundle",
        authorization.role,
        authorization.authorizationId,
      ),
      generatedAt: epochValidFrom,
      registryId: this.registryId,
      subjectDid,
      policy: this.policyRecord,
      epoch: {
        epochId,
        registryId: this.registryId,
        stateRoot,
        eventRoot,
        policyRoot,
        validFrom: epochValidFrom,
        validUntil: epochValidUntil,
        maintainerSignatures: [
          {
            keyId: `${this.maintainerDid}#key-1`,
            algorithm: "jubjub-schnorr",
            signature: bytes32Hex(this.simulator.getLedger().lastGovernanceEventHash),
          },
        ],
      },
      inclusionProof: {
        proofType: "signed-statement",
        root: eventRoot,
        leafHash: bundleLeafHash(authorization),
        path: [stateRoot],
        leafIndex: 0,
      },
      authorization,
      referencedStatusRegistryId,
      referencedStatusPolicyUri: "https://registry.example/status-policy",
    });
  }
}
