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
  computeUpdateRecognitionPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
  computeUpdateVerifierAuthorizationPayloadHash,
  createMaintainerFixture,
  decodeJubjubSignature,
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  labelToBytes32,
  signMaintainerActionFromSeed,
  TrustRegistrySimulator,
  verifyMaintainerAction,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  AuthorizationStatus as ContractAuthorizationStatus,
  type AuditorAuthorizationRecord as ContractAuditorAuthorizationRecord,
  type EpochCommitmentRecord as ContractEpochCommitmentRecord,
  IssuerResourceType,
  type IssuerAuthorizationRecord as ContractIssuerAuthorizationRecord,
  type RecognitionRecord as ContractRecognitionRecord,
  type VerifierAuthorizationRecord as ContractVerifierAuthorizationRecord,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  AuthorizationRecordSchema,
  EpochCommitmentSchema,
  type EpochCommitment,
  GovernancePolicyRecordSchema,
  RecognitionRecordSchema,
  type RegistryRecord,
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
  type AuthorizationRecord,
  type GovernancePolicyRecord,
  type RecognitionRecord,
  type TrustRegistryEvidenceBundle,
  createScopedIdentifier,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  type AuditorScenarioFixture,
  bytes32Commitment,
  createMidnightDid,
  type IssuerScenarioFixture,
  type MaintainerScenarioFixture,
  type RecognitionScenarioFixture,
  type VerifierScenarioFixture,
} from "./fixtures.js";

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
const SUSPEND_AUDITOR_ACTION_KIND = labelToBytes32("tr:auditor:suspend");
const REVOKE_AUDITOR_ACTION_KIND = labelToBytes32("tr:auditor:revoke");
const ARCHIVE_AUDITOR_ACTION_KIND = labelToBytes32("tr:auditor:archive");
const PROPOSE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:propose");
const AUTHORIZE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:authorize");
const ACTIVATE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:activate");
const SUSPEND_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:suspend");
const REVOKE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:revoke");
const ARCHIVE_MAINTAINER_ACTION_KIND = labelToBytes32("tr:maintainer:archive");
const CREATE_EPOCH_ACTION_KIND = labelToBytes32("tr:epoch:publish");

const BASE_TIMESTAMP_MS = Date.parse("2026-05-20T00:00:00Z");

const bytes32Hex = (value: Uint8Array): string =>
  `0x${Buffer.from(value).toString("hex")}`;

const hashHexToBytes32 = (value: string): Uint8Array =>
  Buffer.from(value.replace(/^0x/, ""), "hex");

const timestampForSequence = (sequence: bigint): string =>
  new Date(BASE_TIMESTAMP_MS + Number(sequence) * 60_000).toISOString();

const optionalSequenceTimestamp = (
  sequence: bigint,
  fieldName: string,
): Partial<Record<string, string>> =>
  sequence > 0n ? { [fieldName]: timestampForSequence(sequence) } : {};

const assertUnreachable = (value: never): never => {
  throw new Error(`unexpected enum value: ${String(value)}`);
};

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

  return assertUnreachable(resourceType);
};

const contractStatusName = (
  status: ContractAuthorizationStatus,
): AuthorizationRecord["status"] => {
  switch (status) {
    case ContractAuthorizationStatus.proposed:
      return "proposed";
    case ContractAuthorizationStatus.authorized:
      return "authorized";
    case ContractAuthorizationStatus.active:
      return "active";
    case ContractAuthorizationStatus.suspended:
      return "suspended";
    case ContractAuthorizationStatus.revoked:
      return "revoked";
    case ContractAuthorizationStatus.archived:
      return "archived";
  }

  return assertUnreachable(status);
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

const recognitionLeafHash = (recognition: RecognitionRecord): string =>
  sha256Hex(
    JSON.stringify({
      recognitionId: recognition.recognitionId,
      status: recognition.status,
      recognizedAuthorityDid: recognition.recognizedAuthorityDid,
      recognizedRegistryId: recognition.recognizedRegistryId,
      scope: recognition.scope,
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
  readonly maintainerId: string;
  readonly maintainerIdCommitment: Uint8Array;
  readonly maintainerDid: string;
  readonly maintainerDidCommitment: Uint8Array;

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
    this.maintainerId = createScopedIdentifier(
      "participant",
      "maintainer",
      label,
      "bootstrap",
    );
    this.maintainerIdCommitment = bytes32Commitment(this.maintainerId);
    this.maintainerDid = createMidnightDid(`maintainer:${label}:bootstrap`);
    this.maintainerDidCommitment = bytes32Commitment(this.maintainerDid);
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
      this.maintainerIdCommitment,
      this.maintainerDidCommitment,
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      1n,
    );
  }

  authorizeMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    this.proposeMaintainer(fixture);
    this.approveMaintainer(fixture);
    return this.activateMaintainer(fixture);
  }

  proposeMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    const candidatePublicKey = deriveJubjubPublicKeyFromSeed(fixture.seed);
    const proposedEvidenceHash = bytes32Commitment(
      `${fixture.maintainerId}:propose`,
    );
    const proposeActionSequence = this.simulator.getLedger().governanceActionCount;
    const proposeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      PROPOSE_MAINTAINER_ACTION_KIND,
      computeCreateMaintainerMembershipPayloadHash(
        fixture.maintainerIdCommitment,
        fixture.subjectDidCommitment,
        fixture.keyId,
        candidatePublicKey,
        this.governancePolicyCommitment,
        bytes32Commitment(fixture.trustLevel),
        proposedEvidenceHash,
      ),
      proposeActionSequence,
    );

    return this.simulator.proposeMaintainerMembership(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      proposeSignature,
      fixture.maintainerIdCommitment,
      fixture.subjectDidCommitment,
      fixture.keyId,
      candidatePublicKey,
      this.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
  }

  approveMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    const authorizedEvidenceHash = bytes32Commitment(
      `${fixture.maintainerId}:authorize`,
    );
    const authorizeActionSequence = this.simulator.getLedger().governanceActionCount;
    const authorizeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      AUTHORIZE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        fixture.maintainerIdCommitment,
        this.simulator.getMaintainerMembership(fixture.maintainerIdCommitment)
          .lifecycleEventHash,
        authorizedEvidenceHash,
      ),
      authorizeActionSequence,
    );

    return this.simulator.authorizeMaintainerMembership(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      authorizeSignature,
      fixture.maintainerIdCommitment,
      authorizedEvidenceHash,
    );
  }

  activateMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    const evidenceHash = bytes32Commitment(`${fixture.maintainerId}:activate`);
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      ACTIVATE_MAINTAINER_ACTION_KIND,
      computeUpdateMaintainerMembershipPayloadHash(
        fixture.maintainerIdCommitment,
        this.simulator.getMaintainerMembership(fixture.maintainerIdCommitment)
          .lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    return this.simulator.activateMaintainerMembership(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.maintainerIdCommitment,
      evidenceHash,
    );
  }

  suspendMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    return this.updateMaintainerLifecycle(
      fixture,
      "suspend",
      SUSPEND_MAINTAINER_ACTION_KIND,
    );
  }

  revokeMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    return this.updateMaintainerLifecycle(
      fixture,
      "revoke",
      REVOKE_MAINTAINER_ACTION_KIND,
    );
  }

  archiveMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    return this.updateMaintainerLifecycle(
      fixture,
      "archive",
      ARCHIVE_MAINTAINER_ACTION_KIND,
    );
  }

  authorizeIssuer(fixture: IssuerScenarioFixture): Uint8Array {
    this.proposeIssuer(fixture);
    this.approveIssuer(fixture);
    return this.activateIssuer(fixture);
  }

  proposeIssuer(fixture: IssuerScenarioFixture): Uint8Array {
    const proposedEvidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:propose`,
    );
    const proposeActionSequence = this.simulator.getLedger().governanceActionCount;
    const proposeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      PROPOSE_ISSUER_ACTION_KIND,
      computeCreateIssuerAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        fixture.subjectDidCommitment,
        fixture.resourceType,
        fixture.resourceIdCommitment,
        this.governancePolicyCommitment,
        bytes32Commitment(fixture.trustLevel),
        proposedEvidenceHash,
      ),
      proposeActionSequence,
    );
    return this.simulator.proposeIssuerAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      proposeSignature,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.resourceType,
      fixture.resourceIdCommitment,
      this.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
  }

  approveIssuer(fixture: IssuerScenarioFixture): Uint8Array {
    const authorizedEvidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:authorize`,
    );
    const authorizeActionSequence = this.simulator.getLedger().governanceActionCount;
    const authorizeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      AUTHORIZE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        this.simulator.getIssuerAuthorization(fixture.authorizationIdCommitment)
          .lifecycleEventHash,
        authorizedEvidenceHash,
      ),
      authorizeActionSequence,
    );
    return this.simulator.authorizeIssuerAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      authorizeSignature,
      fixture.authorizationIdCommitment,
      authorizedEvidenceHash,
    );
  }

  activateIssuer(fixture: IssuerScenarioFixture): Uint8Array {
    const evidenceHash = bytes32Commitment(`${fixture.authorizationId}:activate`);
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      ACTIVATE_ISSUER_ACTION_KIND,
      computeUpdateIssuerAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        this.simulator.getIssuerAuthorization(fixture.authorizationIdCommitment)
          .lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    return this.simulator.activateIssuerAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
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

  proposeVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    const proposedEvidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:propose`,
    );
    const proposeActionSequence = this.simulator.getLedger().governanceActionCount;
    const proposeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      PROPOSE_VERIFIER_ACTION_KIND,
      computeCreateVerifierAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        fixture.subjectDidCommitment,
        fixture.requestProfileIdCommitment,
        fixture.allowedAttributeSetCommitment,
        fixture.allowedPredicateSetCommitment,
        fixture.disclosureLevelCommitment,
        this.governancePolicyCommitment,
        bytes32Commitment(fixture.trustLevel),
        proposedEvidenceHash,
      ),
      proposeActionSequence,
    );
    return this.simulator.proposeVerifierAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      proposeSignature,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.requestProfileIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
      this.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
  }

  approveVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    const authorizedEvidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:authorize`,
    );
    const authorizeActionSequence = this.simulator.getLedger().governanceActionCount;
    const authorizeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      AUTHORIZE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        this.simulator.getVerifierAuthorization(fixture.authorizationIdCommitment)
          .lifecycleEventHash,
        authorizedEvidenceHash,
      ),
      authorizeActionSequence,
    );
    return this.simulator.authorizeVerifierAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      authorizeSignature,
      fixture.authorizationIdCommitment,
      authorizedEvidenceHash,
    );
  }

  activateVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    const evidenceHash = bytes32Commitment(`${fixture.authorizationId}:activate`);
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      ACTIVATE_VERIFIER_ACTION_KIND,
      computeUpdateVerifierAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        this.simulator.getVerifierAuthorization(fixture.authorizationIdCommitment)
          .lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    return this.simulator.activateVerifierAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
      evidenceHash,
    );
  }

  authorizeVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    this.proposeVerifier(fixture);
    this.approveVerifier(fixture);
    return this.activateVerifier(fixture);
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

  proposeRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    const proposedEvidenceHash = bytes32Commitment(
      `${fixture.recognitionId}:propose`,
    );
    const proposeActionSequence = this.simulator.getLedger().governanceActionCount;
    const proposeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      PROPOSE_RECOGNITION_ACTION_KIND,
      computeCreateRecognitionPayloadHash(
        fixture.recognitionIdCommitment,
        fixture.recognizedAuthorityDidCommitment,
        fixture.recognizedRegistryIdCommitment,
        fixture.scopeResourceTypeCommitment,
        fixture.scopeResourceIdCommitment,
        this.governancePolicyCommitment,
        bytes32Commitment(fixture.trustLevel),
        proposedEvidenceHash,
      ),
      proposeActionSequence,
    );

    return this.simulator.proposeRecognition(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      proposeSignature,
      fixture.recognitionIdCommitment,
      fixture.recognizedAuthorityDidCommitment,
      fixture.recognizedRegistryIdCommitment,
      fixture.scopeResourceTypeCommitment,
      fixture.scopeResourceIdCommitment,
      this.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
  }

  approveRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    const authorizedEvidenceHash = bytes32Commitment(
      `${fixture.recognitionId}:authorize`,
    );
    const authorizeActionSequence = this.simulator.getLedger().governanceActionCount;
    const authorizeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      AUTHORIZE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        fixture.recognitionIdCommitment,
        this.simulator.getRecognition(fixture.recognitionIdCommitment)
          .lifecycleEventHash,
        authorizedEvidenceHash,
      ),
      authorizeActionSequence,
    );
    return this.simulator.authorizeRecognition(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      authorizeSignature,
      fixture.recognitionIdCommitment,
      authorizedEvidenceHash,
    );
  }

  activateRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    const evidenceHash = bytes32Commitment(`${fixture.recognitionId}:activate`);
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      ACTIVATE_RECOGNITION_ACTION_KIND,
      computeUpdateRecognitionPayloadHash(
        fixture.recognitionIdCommitment,
        this.simulator.getRecognition(fixture.recognitionIdCommitment)
          .lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    return this.simulator.activateRecognition(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.recognitionIdCommitment,
      evidenceHash,
    );
  }

  authorizeRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    this.proposeRecognition(fixture);
    this.approveRecognition(fixture);
    return this.activateRecognition(fixture);
  }

  proposeAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    const proposedEvidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:propose`,
    );
    const proposeActionSequence = this.simulator.getLedger().governanceActionCount;
    const proposeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      PROPOSE_AUDITOR_ACTION_KIND,
      computeCreateAuditorAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        fixture.subjectDidCommitment,
        fixture.requestProfileIdCommitment,
        fixture.allowedAttributeSetCommitment,
        fixture.allowedPredicateSetCommitment,
        fixture.disclosureLevelCommitment,
        this.governancePolicyCommitment,
        bytes32Commitment(fixture.trustLevel),
        proposedEvidenceHash,
      ),
      proposeActionSequence,
    );
    return this.simulator.proposeAuditorAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      proposeSignature,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.requestProfileIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
      this.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
  }

  approveAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    const authorizedEvidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:authorize`,
    );
    const authorizeActionSequence = this.simulator.getLedger().governanceActionCount;
    const authorizeSignature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      AUTHORIZE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        this.simulator.getAuditorAuthorization(fixture.authorizationIdCommitment)
          .lifecycleEventHash,
        authorizedEvidenceHash,
      ),
      authorizeActionSequence,
    );
    return this.simulator.authorizeAuditorAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      authorizeSignature,
      fixture.authorizationIdCommitment,
      authorizedEvidenceHash,
    );
  }

  activateAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    const evidenceHash = bytes32Commitment(`${fixture.authorizationId}:activate`);
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      ACTIVATE_AUDITOR_ACTION_KIND,
      computeUpdateAuditorAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        this.simulator.getAuditorAuthorization(fixture.authorizationIdCommitment)
          .lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );
    return this.simulator.activateAuditorAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
      evidenceHash,
    );
  }

  authorizeAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    this.proposeAuditor(fixture);
    this.approveAuditor(fixture);
    return this.activateAuditor(fixture);
  }

  suspendAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    return this.updateAuditorLifecycle(
      fixture,
      "suspend",
      SUSPEND_AUDITOR_ACTION_KIND,
    );
  }

  revokeAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    return this.updateAuditorLifecycle(
      fixture,
      "revoke",
      REVOKE_AUDITOR_ACTION_KIND,
    );
  }

  archiveAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    return this.updateAuditorLifecycle(
      fixture,
      "archive",
      ARCHIVE_AUDITOR_ACTION_KIND,
    );
  }

  suspendRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    return this.updateRecognitionLifecycle(
      fixture,
      "suspend",
      SUSPEND_RECOGNITION_ACTION_KIND,
    );
  }

  revokeRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    return this.updateRecognitionLifecycle(
      fixture,
      "revoke",
      REVOKE_RECOGNITION_ACTION_KIND,
    );
  }

  archiveRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    return this.updateRecognitionLifecycle(
      fixture,
      "archive",
      ARCHIVE_RECOGNITION_ACTION_KIND,
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
    const bundle = this.buildIssuerHistoricalEvidence(fixture);
    this.assertPublishedEpochEvidence(bundle);
    return bundle;
  }

  buildIssuerHistoricalEvidence(
    fixture: IssuerScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    const record = this.simulator.getIssuerAuthorization(
      fixture.authorizationIdCommitment,
    );
    const authorization = this.buildIssuerAuthorizationRecord(fixture, record);
    return this.buildEvidenceBundle({
      authorization,
      subjectDid: fixture.subjectDid,
      referencedStatusRegistryId: fixture.referencedStatusRegistryId,
      lastStatusSequence: record.lastStatusSequence,
    });
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
    const bundle = this.buildVerifierHistoricalEvidence(fixture);
    this.assertPublishedEpochEvidence(bundle);
    return bundle;
  }

  buildVerifierHistoricalEvidence(
    fixture: VerifierScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    const record = this.simulator.getVerifierAuthorization(
      fixture.authorizationIdCommitment,
    );
    const authorization = this.buildVerifierAuthorizationRecord(fixture, record);
    return this.buildEvidenceBundle({
      authorization,
      subjectDid: fixture.subjectDid,
      referencedStatusRegistryId: fixture.referencedStatusRegistryId,
      lastStatusSequence: record.lastStatusSequence,
    });
  }

  evaluateCurrentAuditorDecision(
    fixture: AuditorScenarioFixture,
    options: { expectedRegistryId?: string } = {},
  ): TrustRegistryEvidenceBundle {
    this.assertRegistryId(options.expectedRegistryId);
    this.simulator.assertAuditorAuthorized(
      fixture.subjectDidCommitment,
      fixture.requestProfileIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
    );
    const bundle = this.buildAuditorHistoricalEvidence(fixture);
    this.assertPublishedEpochEvidence(bundle);
    return bundle;
  }

  evaluateCurrentRecognitionDecision(
    fixture: RecognitionScenarioFixture,
    options: { expectedRegistryId?: string } = {},
  ): TrustRegistryEvidenceBundle {
    this.assertRegistryId(options.expectedRegistryId);
    this.simulator.assertRecognitionActive(
      fixture.recognizedAuthorityDidCommitment,
      fixture.recognizedRegistryIdCommitment,
      fixture.scopeResourceTypeCommitment,
      fixture.scopeResourceIdCommitment,
    );
    const bundle = this.buildRecognitionHistoricalEvidence(fixture);
    this.assertPublishedEpochEvidence(bundle);
    return bundle;
  }

  assertPublishedEpochEvidence(
    bundle: TrustRegistryEvidenceBundle,
    options: { evaluationTime?: string } = {},
  ): void {
    this.assertRegistryId(bundle.registryId);
    const epochRecord = this.simulator.getEpochCommitment(
      bytes32Commitment(bundle.epoch.epochId),
    );
    const expectedStateRoot = bytes32Hex(epochRecord.stateRoot);
    const expectedEventRoot = bytes32Hex(epochRecord.eventRoot);
    const expectedPolicyRoot = bytes32Hex(epochRecord.policyRoot);

    if (bundle.epoch.stateRoot !== expectedStateRoot) {
      throw new Error(
        `Epoch state root mismatch: expected ${expectedStateRoot}, got ${bundle.epoch.stateRoot}`,
      );
    }
    if (bundle.epoch.eventRoot !== expectedEventRoot) {
      throw new Error(
        `Epoch event root mismatch: expected ${expectedEventRoot}, got ${bundle.epoch.eventRoot}`,
      );
    }
    if (bundle.epoch.policyRoot !== expectedPolicyRoot) {
      throw new Error(
        `Epoch policy root mismatch: expected ${expectedPolicyRoot}, got ${bundle.epoch.policyRoot}`,
      );
    }
    if (bundle.epoch.registryId !== this.registryId) {
      throw new Error(
        `Epoch registry mismatch: expected ${this.registryId}, got ${bundle.epoch.registryId}`,
      );
    }

    const evaluationTime = Date.parse(options.evaluationTime ?? bundle.generatedAt);
    if (evaluationTime < Date.parse(bundle.epoch.validFrom)) {
      throw new Error("Epoch is not yet valid for this evidence bundle");
    }
    if (evaluationTime > Date.parse(bundle.epoch.validUntil)) {
      throw new Error("Epoch is stale for this evidence bundle");
    }

    const maintainerSignature = bundle.epoch.maintainerSignatures.at(0);
    if (maintainerSignature === undefined) {
      throw new Error("Epoch commitment must include at least one maintainer signature");
    }
    const encodedSignature = Buffer.from(
      maintainerSignature.signature.replace(/^0x/, ""),
      "hex",
    );
    const signature = decodeJubjubSignature(encodedSignature);
    const payloadHash = computeCreateEpochCommitmentPayloadHash(
      bytes32Commitment(bundle.epoch.epochId),
      hashHexToBytes32(bundle.epoch.stateRoot),
      hashHexToBytes32(bundle.epoch.eventRoot),
      hashHexToBytes32(bundle.epoch.policyRoot),
      epochRecord.validFromSequence,
      epochRecord.validUntilSequence,
    );
    const maintainerRecord = this.simulator
      .getLedger()
      .maintainerRecords.lookup(epochRecord.maintainerKeyId);
    const verified = verifyMaintainerAction(
      maintainerRecord.publicKey,
      this.registryIdCommitment,
      CREATE_EPOCH_ACTION_KIND,
      payloadHash,
      epochRecord.publishedAtSequence,
      signature,
    );
    if (!verified) {
      throw new Error("Epoch maintainer signature is invalid");
    }
  }

  buildRecognitionHistoricalEvidence(
    fixture: RecognitionScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    const record = this.simulator.getRecognition(fixture.recognitionIdCommitment);
    const recognition = this.buildRecognitionRecord(fixture, record);
    return this.buildEvidenceBundle({
      subjectDid: fixture.recognizedAuthorityDid,
      lastStatusSequence: record.lastStatusSequence,
      recognition,
    });
  }

  buildAuditorHistoricalEvidence(
    fixture: AuditorScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    const record = this.simulator.getAuditorAuthorization(
      fixture.authorizationIdCommitment,
    );
    const authorization = this.buildAuditorAuthorizationRecord(fixture, record);
    return this.buildEvidenceBundle({
      authorization,
      subjectDid: fixture.subjectDid,
      lastStatusSequence: record.lastStatusSequence,
    });
  }

  private updateMaintainerLifecycle(
    fixture: MaintainerScenarioFixture,
    actionName: "suspend" | "revoke" | "archive",
    actionKind: Uint8Array,
  ): Uint8Array {
    const evidenceHash = bytes32Commitment(
      `${fixture.maintainerId}:${actionName}`,
    );
    const currentRecord = this.simulator.getMaintainerMembership(
      fixture.maintainerIdCommitment,
    );
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      actionKind,
      computeUpdateMaintainerMembershipPayloadHash(
        fixture.maintainerIdCommitment,
        currentRecord.lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    if (actionName === "suspend") {
      return this.simulator.suspendMaintainerMembership(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.maintainerIdCommitment,
        evidenceHash,
      );
    }

    if (actionName === "revoke") {
      return this.simulator.revokeMaintainerMembership(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.maintainerIdCommitment,
        evidenceHash,
      );
    }

    return this.simulator.archiveMaintainerMembership(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.maintainerIdCommitment,
      evidenceHash,
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

  private updateAuditorLifecycle(
    fixture: AuditorScenarioFixture,
    actionName: "suspend" | "revoke" | "archive",
    actionKind: Uint8Array,
  ): Uint8Array {
    const evidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:${actionName}`,
    );
    const currentRecord = this.simulator.getAuditorAuthorization(
      fixture.authorizationIdCommitment,
    );
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      actionKind,
      computeUpdateAuditorAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        currentRecord.lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    if (actionName === "suspend") {
      return this.simulator.suspendAuditorAuthorization(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.authorizationIdCommitment,
        evidenceHash,
      );
    }
    if (actionName === "revoke") {
      return this.simulator.revokeAuditorAuthorization(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.authorizationIdCommitment,
        evidenceHash,
      );
    }
    return this.simulator.archiveAuditorAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
      evidenceHash,
    );
  }

  private updateRecognitionLifecycle(
    fixture: RecognitionScenarioFixture,
    actionName: "suspend" | "revoke" | "archive",
    actionKind: Uint8Array,
  ): Uint8Array {
    const evidenceHash = bytes32Commitment(
      `${fixture.recognitionId}:${actionName}`,
    );
    const currentRecord = this.simulator.getRecognition(
      fixture.recognitionIdCommitment,
    );
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const signature = signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      actionKind,
      computeUpdateRecognitionPayloadHash(
        fixture.recognitionIdCommitment,
        currentRecord.lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence,
    );

    if (actionName === "suspend") {
      return this.simulator.suspendRecognition(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.recognitionIdCommitment,
        evidenceHash,
      );
    }
    if (actionName === "revoke") {
      return this.simulator.revokeRecognition(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.recognitionIdCommitment,
        evidenceHash,
      );
    }
    return this.simulator.archiveRecognition(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.recognitionIdCommitment,
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

  private buildAuditorAuthorizationRecord(
    fixture: AuditorScenarioFixture,
    record: ContractAuditorAuthorizationRecord,
  ): AuthorizationRecord {
    return this.buildAuthorizationRecord({
      authorizationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      role: "auditor",
      resourceType: "request-profile",
      resourceId: fixture.scopeResourceId,
      trustLevel: fixture.trustLevel,
      record,
    });
  }

  private buildRecognitionRecord(
    fixture: RecognitionScenarioFixture,
    record: ContractRecognitionRecord,
  ): RecognitionRecord {
    const status = contractStatusName(record.status);

    return RecognitionRecordSchema.parse({
      recognitionId: fixture.recognitionId,
      registryId: this.registryId,
      recognizedAuthorityDid: fixture.recognizedAuthorityDid,
      recognizedRegistryId: fixture.recognizedRegistryId,
      scope: {
        resourceType: fixture.scopeResourceType,
        resourceId: fixture.scopeResourceId,
      },
      policyId: this.policyId,
      trustLevel: fixture.trustLevel,
      status,
      proposedAt: timestampForSequence(record.proposedAtSequence),
      ...(record.authorizedAtSequence > 0n
        ? { authorizedAt: timestampForSequence(record.authorizedAtSequence) }
        : {}),
      ...(record.effectiveFromSequence > 0n
        ? { effectiveFrom: timestampForSequence(record.effectiveFromSequence) }
        : {}),
      ...optionalSequenceTimestamp(record.suspendedAtSequence, "suspendedAt"),
      ...optionalSequenceTimestamp(record.revokedAtSequence, "revokedAt"),
      ...optionalSequenceTimestamp(record.archivedAtSequence, "archivedAt"),
      evidenceHash: bytes32Hex(record.evidenceHash),
      lifecycleEventRoot: bytes32Hex(record.lifecycleEventHash),
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
      | ContractVerifierAuthorizationRecord
      | ContractAuditorAuthorizationRecord;
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

  private ensurePublishedEpochCommitment(input: {
    statementId: string;
    lastStatusSequence: bigint;
    lifecycleEventRoot: string;
    statementStatus: string;
  }): EpochCommitment {
    const epochId = createScopedIdentifier(
      "epoch",
      this.registryId,
      `seq-${input.lastStatusSequence.toString()}`,
    );
    const epochIdCommitment = bytes32Commitment(epochId);
    const epochValidFromSequence = input.lastStatusSequence;
    const epochValidUntilSequence = input.lastStatusSequence + 60n;
    const stateRoot = sha256Hex(
      JSON.stringify({
        registryId: this.registryId,
        statementId: input.statementId,
        status: input.statementStatus,
        lifecycleEventRoot: input.lifecycleEventRoot,
      }),
    );
    const eventRoot = input.lifecycleEventRoot;
    const policyRoot = bytes32Hex(this.governancePolicyCommitment);

    let record: ContractEpochCommitmentRecord;
    try {
      record = this.simulator.getEpochCommitment(epochIdCommitment);
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      if (!/not registered/i.test(message)) {
        throw error;
      }

      const actionSequence = this.simulator.getLedger().governanceActionCount;
      const signature = signMaintainerActionFromSeed(
        this.bootstrapMaintainer.seed,
        this.registryIdCommitment,
        CREATE_EPOCH_ACTION_KIND,
        computeCreateEpochCommitmentPayloadHash(
          epochIdCommitment,
          hashHexToBytes32(stateRoot),
          hashHexToBytes32(eventRoot),
          hashHexToBytes32(policyRoot),
          epochValidFromSequence,
          epochValidUntilSequence,
        ),
        actionSequence,
      );
      this.simulator.publishEpochCommitment(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        epochIdCommitment,
        hashHexToBytes32(stateRoot),
        hashHexToBytes32(eventRoot),
        hashHexToBytes32(policyRoot),
        epochValidFromSequence,
        epochValidUntilSequence,
      );
      record = this.simulator.getEpochCommitment(epochIdCommitment);
    }

    return this.buildEpochCommitment(epochId, record);
  }

  private buildEpochCommitment(
    epochId: string,
    record: ContractEpochCommitmentRecord,
  ): EpochCommitment {
    return EpochCommitmentSchema.parse({
      epochId,
      registryId: this.registryId,
      stateRoot: bytes32Hex(record.stateRoot),
      eventRoot: bytes32Hex(record.eventRoot),
      policyRoot: bytes32Hex(record.policyRoot),
      validFrom: timestampForSequence(record.validFromSequence),
      validUntil: timestampForSequence(record.validUntilSequence),
      maintainerSignatures: [
        {
          keyId: `${this.maintainerDid}#key-1`,
          algorithm: "jubjub-schnorr",
          signature: bytes32Hex(
            encodeJubjubSignature({
              announcement: record.signatureAnnouncement,
              response: record.signatureResponse,
            }),
          ),
        },
      ],
    });
  }

  private buildEvidenceBundle(input: {
    subjectDid: string;
    lastStatusSequence: bigint;
    authorization?: AuthorizationRecord;
    recognition?: RecognitionRecord;
    referencedStatusRegistryId?: string;
  }): TrustRegistryEvidenceBundle {
    const bundleRole = input.authorization?.role ?? "recognition";
    const bundleSubjectId =
      input.authorization?.authorizationId ?? input.recognition?.recognitionId;
    const statementStatus =
      input.authorization?.status ?? input.recognition?.status;
    const lifecycleEventRoot =
      input.authorization?.lifecycleEventRoot
      ?? input.recognition?.lifecycleEventRoot;
    const epoch = this.ensurePublishedEpochCommitment({
      statementId: bundleSubjectId ?? "missing",
      lastStatusSequence: input.lastStatusSequence,
      lifecycleEventRoot: lifecycleEventRoot ?? sha256Hex("missing"),
      statementStatus: statementStatus ?? "unknown",
    });

    return TrustRegistryEvidenceBundleSchema.parse({
      bundleId: createScopedIdentifier(
        "bundle",
        bundleRole,
        bundleSubjectId ?? "missing",
      ),
      generatedAt: epoch.validFrom,
      registryId: this.registryId,
      subjectDid: input.subjectDid,
      policy: this.policyRecord,
      epoch,
      inclusionProof: {
        proofType: "signed-statement",
        root: epoch.eventRoot,
        leafHash:
          input.authorization !== undefined
            ? bundleLeafHash(input.authorization)
            : recognitionLeafHash(input.recognition!),
        path: [epoch.stateRoot],
        leafIndex: 0,
      },
      ...(input.authorization !== undefined
        ? {
            authorization: input.authorization,
            referencedStatusRegistryId: input.referencedStatusRegistryId,
            referencedStatusPolicyUri: "https://registry.example/status-policy",
          }
        : {}),
      ...(input.recognition !== undefined
        ? {
            recognition: input.recognition,
          }
        : {}),
    });
  }
}
