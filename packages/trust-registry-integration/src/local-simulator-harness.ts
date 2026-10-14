import { Buffer } from "node:buffer";

import {
  computeCreateAuditorAuthorizationPayloadHash,
  computeAuditorEvidenceBoundProposalPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  computeCreateEpochCommitmentPayloadHash,
  computeCreateMaintainerMembershipPayloadHash,
  computeCreateRecognitionPayloadHash,
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateEvidenceVerifierKeyPayloadHash,
  computeUpdateVcAuthorityKeyPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeUpdateAuditorAuthorizationPayloadHash,
  computeUpdateMaintainerMembershipPayloadHash,
  computeUpdateMaintainerThresholdPolicyPayloadHash,
  computeUpdateRecognitionPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
  computeUpdateVerifierAuthorizationPayloadHash,
  decodeCanonicalJubjubSignatureHex,
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  encodeCompactActionKind,
  computeIssuerEvidenceBoundProposalPayloadHash,
  computeVerifierEvidenceBoundProposalPayloadHash,
  signApplicationEvidenceCommitmentFromSeed,
  signAuditorProposalEvidenceFromSeed,
  signMaintainerProposalEvidenceFromSeed,
  signIssuerProposalEvidenceFromSeed,
  signVerifierProposalEvidenceFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
  type TrustRegistryJubjubSignature,
  verifyApplicationEvidenceCommitmentSignature,
  verifyPolicyBoundMaintainerAction,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  createMaintainerFixture,
  labelToBytes32,
  type MaintainerCoAuthorizer,
  TrustRegistrySimulator,
} from "@midnight-ntwrk/trust-registry-contract/testing";
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
  AuthorizationScopeSchema,
  assertValidApplicationEvidence,
  computeApplicationEvidenceCommitment,
  computeAuthorizationScopeCommitment,
  computeGovernancePolicySnapshotCommitment,
  computeIssuerStatusPolicyBindingCommitment,
  EpochCommitmentSchema,
  type ApplicationEvidenceSubmission,
  type ApplicationEvidenceSignature,
  type AuthorizationScope,
  type ApplicationEvidenceRole,
  type AuthorizedEvidenceVerifier,
  type EpochCommitment,
  GovernancePolicyRecordSchema,
  RecognitionRecordSchema,
  type RegistryRecord,
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
  type AuthorizationRecord,
  type IssuerStatusPolicyBinding,
  type GovernancePolicyRecord,
  type GovernedResource,
  type RecognitionRecord,
  type TrustRegistryEvidenceBundle,
  assertGovernancePolicyRevision,
  computeAuthorizationStatementLeafHash,
  computeRecognitionStatementLeafHash,
  computeRegistryStatementLeafHash,
  computeSingleStatementStateRoot,
  createScopedIdentifier,
  deriveGovernancePolicySnapshot,
  governedResourceInScope,
  requestGovernedResourceId,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  type AuditorScenarioFixture,
  bytes32Commitment,
  createAuditorAuthorizationScopeFixture,
  createIssuerAuthorizationScopeFixture,
  createMaintainerAuthorizationScopeFixture,
  createMidnightDid,
  createVerifierAuthorizationScopeFixture,
  type IssuerScenarioFixture,
  issuerResourceTypeDetails,
  type MaintainerScenarioFixture,
  type RecognitionScenarioFixture,
  type VerifierScenarioFixture,
} from "./fixtures.js";
import { prepareVcAuthorityKeyRegistration } from "./vc-authority-registration.js";
import type { VcAuthorityDomain } from "./vc-signer-authorization.js";

const PROPOSE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:propose");
const REGISTER_EVIDENCE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:evidence-verifier:register");
const REGISTER_VC_AUTHORITY_KEY_ACTION_KIND = encodeCompactActionKind("tr:vc-authority:key:register");
const SUSPEND_VC_AUTHORITY_KEY_ACTION_KIND = encodeCompactActionKind("tr:vc-authority:key:suspend");
const AUTHORIZE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:authorize");
const ACTIVATE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:activate");
const SUSPEND_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:suspend");
const REVOKE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:revoke");
const ARCHIVE_ISSUER_ACTION_KIND = encodeCompactActionKind("tr:issuer:archive");
const PROPOSE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:propose");
const AUTHORIZE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:authorize");
const ACTIVATE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:activate");
const SUSPEND_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:suspend");
const REVOKE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:revoke");
const ARCHIVE_VERIFIER_ACTION_KIND = encodeCompactActionKind("tr:verifier:archive");
const PROPOSE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:propose");
const AUTHORIZE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:authorize");
const ACTIVATE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:activate");
const SUSPEND_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:suspend");
const REVOKE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:revoke");
const ARCHIVE_RECOGNITION_ACTION_KIND = encodeCompactActionKind("tr:recognition:archive");
const PROPOSE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:propose");
const AUTHORIZE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:authorize");
const ACTIVATE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:activate");
const SUSPEND_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:suspend");
const REVOKE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:revoke");
const ARCHIVE_AUDITOR_ACTION_KIND = encodeCompactActionKind("tr:auditor:archive");
const PROPOSE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:propose");
const AUTHORIZE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:authorize");
const ACTIVATE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:activate");
const SUSPEND_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:suspend");
const REVOKE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:revoke");
const ARCHIVE_MAINTAINER_ACTION_KIND = encodeCompactActionKind("tr:maintainer:archive");
const UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND = encodeCompactActionKind(
  "tr:policy:thresholds:update",
);
const CREATE_EPOCH_ACTION_KIND = encodeCompactActionKind("tr:epoch:publish");

const BASE_TIMESTAMP_MS = Date.parse("2026-05-20T00:00:00Z");

export type SimulatorApplicationEvidenceExpectation = {
  scope: AuthorizationScope;
  challengeHash: string;
  governedResource: GovernedResource;
};

export type IssuerDecisionAction = "approve" | "activate" | "suspend" | "revoke";

export type PreparedIssuerDecisionAction = {
  registryId: Uint8Array;
  authorizationId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  previousLifecycleEventHash: Uint8Array;
  evidenceHash: Uint8Array;
};

export type PreparedIssuerProposalAction = {
  registryId: Uint8Array;
  authorizationId: Uint8Array;
  policyCommitment: Uint8Array;
  policyVersion: bigint;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  evidenceHash: Uint8Array;
  statusPolicyBindingCommitment: Uint8Array;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
};

type PreparedRequestProposalAction = Pick<PreparedIssuerDecisionAction,
  "registryId" | "authorizationId" | "policyCommitment" | "actionKind" |
  "actionPayloadHash" | "actionSequence" | "evidenceHash">;

export type PreparedAuditorProposalAction = PreparedRequestProposalAction & {
  policyVersion: bigint;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
};

export type PreparedVerifierProposalAction = PreparedRequestProposalAction & {
  policyVersion: bigint;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
};

export type PreparedRecognitionAction = {
  registryId: Uint8Array;
  recognitionId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  evidenceHash: Uint8Array;
  previousLifecycleEventHash?: Uint8Array;
};

export type PreparedMaintainerAction = {
  registryId: Uint8Array;
  maintainerId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  evidenceHash: Uint8Array;
  previousLifecycleEventHash?: Uint8Array;
};

export type PreparedMaintainerProposalAction = PreparedMaintainerAction & {
  policyVersion: bigint;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
};

export type PreparedRegistryEpochPublicationAction = {
  epochId: string;
  registryId: Uint8Array;
  epochIdCommitment: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  stateRoot: Uint8Array;
  eventRoot: Uint8Array;
  policyRoot: Uint8Array;
  validFromSequence: bigint;
  validUntilSequence: bigint;
};

export type PreparedThresholdPolicyRevisionAction = {
  registryId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  nextPolicyCommitment: Uint8Array;
  nextPolicyVersion: bigint;
};

export type PreparedEvidenceVerifierRegistrationAction = {
  registryId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  authorizationId: Uint8Array;
  keyIdCommitment: Uint8Array;
  policyVersion: bigint;
};

const defaultGovernedResource = (scope: AuthorizationScope): GovernedResource => {
  if (scope.role === "issuer") throw new Error("Issuer application evidence requires an explicit governed resource");
  if (scope.role === "maintainer") return { type: "registry", id: scope.registryId };
  return { type: "requestProfile", id: requestGovernedResourceId(scope) };
};

const issuerGovernedResource = (fixture: IssuerScenarioFixture): GovernedResource => {
  const type = issuerResourceTypeDetails[fixture.resourceType]?.governedType;
  if (type === undefined) throw new Error("Issuer resource type is invalid");
  return { type, id: fixture.resourceId };
};

const defaultIssuerEvidenceExpectation = (
  fixture: IssuerScenarioFixture,
): SimulatorApplicationEvidenceExpectation => ({
  scope: createIssuerAuthorizationScopeFixture(fixture),
  challengeHash: sha256Hex(`challenge:${fixture.authorizationId}`),
  governedResource: issuerGovernedResource(fixture),
});

const bytes32Hex = (value: Uint8Array): string =>
  `0x${Buffer.from(value).toString("hex")}`;

const hashHexToBytes32 = (value: string): Uint8Array =>
  Buffer.from(value.replace(/^0x/, ""), "hex");

const sameBytes = (left: Uint8Array, right: Uint8Array): boolean =>
  Buffer.from(left).equals(Buffer.from(right));

const thresholdToPolicyNumber = (threshold: bigint): number => {
  if (threshold > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("Maintainer threshold exceeds Number.MAX_SAFE_INTEGER");
  }

  return Number(threshold);
};

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
): AuthorizationRecord["resourceType"] => issuerResourceTypeDetails[resourceType].recordType;

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

export class LocalTrustRegistryIntegrationHarness {
  readonly simulator: TrustRegistrySimulator;
  readonly registryId: string;
  readonly registryDid: string;
  readonly registryIdCommitment: Uint8Array;
  readonly registryDidCommitment: Uint8Array;
  readonly policyId: string;
  governancePolicyCommitment: Uint8Array;
  registryRecord: RegistryRecord;
  readonly maintainerId: string;
  readonly maintainerIdCommitment: Uint8Array;
  readonly maintainerDid: string;
  readonly maintainerDidCommitment: Uint8Array;
  readonly evidenceVerifier: AuthorizedEvidenceVerifier;
  private currentEvidenceVerifierAuthorizationId!: Uint8Array;
  private currentEvidenceVerifierKeyIdCommitment!: Uint8Array;

  private readonly bootstrapMaintainer = createMaintainerFixture("bootstrap", 17);
  private readonly evidenceVerifierKey = createMaintainerFixture("evidence-verifier", 41);
  private readonly evidenceVerifierPublicKey = deriveJubjubPublicKeyFromSeed(
    this.evidenceVerifierKey.seed,
  );
  private readonly bootstrapPublicKey = deriveJubjubPublicKeyFromSeed(
    this.bootstrapMaintainer.seed,
  );
  private readonly knownMaintainers = new Map<string, MaintainerScenarioFixture>();
  private readonly epochPublicationWitnesses = new Map<string, {
    eventHash: string;
    signatures: Array<{ keyId: string; algorithm: "jubjub-schnorr"; signature: string }>;
  }>();
  private readonly issuerApplicationEvidence = new Map<string, {
    evidence: ApplicationEvidenceSubmission;
    challengeHash: string;
  }>();
  private policyRecordValue: GovernancePolicyRecord;
  private evidenceTimeMs = BASE_TIMESTAMP_MS;
  private readonly policyRevisions: Array<{
    effectiveFromSequence: bigint;
    commitment: Uint8Array;
    record: GovernancePolicyRecord;
  }> = [];

  get policyRecord(): GovernancePolicyRecord {
    return this.policyRecordValue;
  }

  advanceEvidenceTimeBy(milliseconds: number): void {
    if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) {
      throw new RangeError("Evidence clock advance must be a nonnegative safe integer");
    }
    const nextEvidenceTimeMs = this.evidenceTimeMs + milliseconds;
    if (
      !Number.isSafeInteger(nextEvidenceTimeMs)
      || Number.isNaN(new Date(nextEvidenceTimeMs).getTime())
    ) {
      throw new RangeError("Evidence clock exceeds the supported timestamp range");
    }
    this.evidenceTimeMs = nextEvidenceTimeMs;
  }

  private evidenceTime(): string {
    return new Date(this.evidenceTimeMs).toISOString();
  }

  constructor(label = "kanon") {
    this.simulator = new TrustRegistrySimulator();
    this.registryId = createScopedIdentifier("registry", label, "trusted");
    this.registryDid = createMidnightDid(`registry:${label}`);
    this.registryIdCommitment = bytes32Commitment(this.registryId);
    this.registryDidCommitment = bytes32Commitment(this.registryDid);
    this.policyId = createScopedIdentifier("policy", label, "v1");
    this.maintainerId = createScopedIdentifier(
      "participant",
      "maintainer",
      label,
      "bootstrap",
    );
    this.maintainerIdCommitment = bytes32Commitment(this.maintainerId);
    this.maintainerDid = createMidnightDid(`maintainer:${label}:bootstrap`);
    this.maintainerDidCommitment = bytes32Commitment(this.maintainerDid);
    this.bootstrapMaintainer.keyId = bytes32Commitment(`${this.maintainerDid}#key-1`);
    this.evidenceVerifier = {
      did: createMidnightDid(`evidence-verifier:${label}`),
      keyIds: [createMidnightDid(`evidence-verifier:${label}`) + "#assertion-1"],
      algorithms: ["jubjub-schnorr"],
    };
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
    this.policyRecordValue = this.buildPolicyRecord(1n, 1n, 1n);
    this.governancePolicyCommitment = hashHexToBytes32(
      computeGovernancePolicySnapshotCommitment(
        deriveGovernancePolicySnapshot(this.policyRecordValue),
      ),
    );
    this.policyRevisions.push({
      effectiveFromSequence: 0n,
      commitment: this.governancePolicyCommitment,
      record: this.policyRecordValue,
    });
    this.knownMaintainers.set(bytes32Hex(this.maintainerIdCommitment), {
      maintainerId: this.maintainerId,
      maintainerIdCommitment: this.maintainerIdCommitment,
      subjectDid: this.maintainerDid,
      subjectDidCommitment: this.maintainerDidCommitment,
      keyId: this.bootstrapMaintainer.keyId,
      seed: this.bootstrapMaintainer.seed,
      trustLevel: "bootstrap-maintainer",
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
    this.authorizeEvidenceVerifierForCurrentPolicy();
  }

  private authorizeEvidenceVerifierForCurrentPolicy(): void {
    const prepared = this.prepareEvidenceVerifierRegistrationAction();
    this.executeEvidenceVerifierRegistrationWithSignatures([
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
      ),
    ]);
  }

  prepareEvidenceVerifierRegistrationAction(): PreparedEvidenceVerifierRegistrationAction {
    const version = this.simulator.getLedger().governancePolicyVersion;
    const keyId = `${this.evidenceVerifier.did}#assertion-${version.toString()}`;
    const authorizationId = bytes32Commitment(
      createScopedIdentifier("evidence-verifier-key", this.registryId, `v${version.toString()}`),
    );
    const didCommitment = bytes32Commitment(this.evidenceVerifier.did);
    const keyIdCommitment = bytes32Commitment(keyId);
    const actionPayloadHash = computeCreateEvidenceVerifierKeyPayloadHash(
      authorizationId,
      didCommitment,
      keyIdCommitment,
      this.evidenceVerifierPublicKey,
      labelToBytes32("jubjub-schnorr"),
      this.governancePolicyCommitment,
      version,
    );
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      policyCommitment: Uint8Array.from(this.governancePolicyCommitment),
      actionKind: Uint8Array.from(REGISTER_EVIDENCE_VERIFIER_ACTION_KIND),
      actionPayloadHash,
      actionSequence,
      authorizationId,
      keyIdCommitment,
      policyVersion: version,
    };
  }

  /** Registration is a distinct governance action after a policy revision. */
  executeEvidenceVerifierRegistrationWithSignatures(
    signers: readonly MaintainerCoAuthorizer[],
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Evidence-verifier registration requires a maintainer signature");
    const prepared = this.prepareEvidenceVerifierRegistrationAction();
    const keyId = `${this.evidenceVerifier.did}#assertion-${prepared.policyVersion.toString()}`;
    this.simulator.registerEvidenceVerifierKey(
      primary.keyId,
      primary.publicKey,
      primary.signature,
      prepared.authorizationId,
      bytes32Commitment(this.evidenceVerifier.did),
      prepared.keyIdCommitment,
      this.evidenceVerifierPublicKey,
      labelToBytes32("jubjub-schnorr"),
      this.governancePolicyCommitment,
      prepared.policyVersion,
      signers.slice(1),
    );
    this.currentEvidenceVerifierAuthorizationId = prepared.authorizationId;
    this.currentEvidenceVerifierKeyIdCommitment = prepared.keyIdCommitment;
    if (this.evidenceVerifier.keyIds[0] !== keyId) this.evidenceVerifier.keyIds.unshift(keyId);
    return prepared.authorizationId;
  }

  registerVcAuthorityKey(input: {
    domain: VcAuthorityDomain;
    keyIdCommitment: Uint8Array;
    publicKey: ReturnType<typeof deriveJubjubPublicKeyFromSeed>;
  }): void {
    const policyCommitment = this.simulator.getLedger().governancePolicyCommitment;
    const policyVersion = this.simulator.getLedger().governancePolicyVersion;
    const prepared = prepareVcAuthorityKeyRegistration({
      domain: input.domain,
      registryId: this.registryId,
      registryContractAddress: `0x${this.simulator.contractAddress}`,
      keyIdCommitment: input.keyIdCommitment,
      publicKey: input.publicKey,
      policyCommitment,
      policyVersion,
    });
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    this.simulator.registerVcAuthorityKey(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      this.bootstrapActionSignature(REGISTER_VC_AUTHORITY_KEY_ACTION_KIND, prepared.payloadHash, actionSequence),
      prepared.keyIdCommitment,
      prepared.authorityDidCommitment,
      prepared.authorityMethodIdCommitment,
      prepared.publicKey,
      prepared.networkIdCommitment,
      prepared.consumerContractAddress,
      prepared.policyCommitment,
      prepared.policyVersion,
      this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        REGISTER_VC_AUTHORITY_KEY_ACTION_KIND,
        prepared.payloadHash,
        actionSequence,
      ),
    );
  }

  suspendVcAuthorityKey(keyIdCommitment: Uint8Array, reasonHash: Uint8Array): void {
    const previous = this.simulator.getVcAuthorityKey(keyIdCommitment);
    const payload = computeUpdateVcAuthorityKeyPayloadHash(
      keyIdCommitment,
      previous.lifecycleEventHash,
      reasonHash,
    );
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    this.simulator.suspendVcAuthorityKey(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      this.bootstrapActionSignature(SUSPEND_VC_AUTHORITY_KEY_ACTION_KIND, payload, actionSequence),
      keyIdCommitment,
      reasonHash,
      this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        SUSPEND_VC_AUTHORITY_KEY_ACTION_KIND,
        payload,
        actionSequence,
      ),
    );
  }

  createApplicationEvidence(input: {
    applicationId: string;
    subjectDid: string;
    role: ApplicationEvidenceRole;
    scope: AuthorizationScope;
    governedResource?: GovernedResource;
  }): ApplicationEvidenceSubmission {
    const scope = AuthorizationScopeSchema.parse(input.scope);
    if (scope.role !== input.role) throw new Error("Application evidence scope role does not match applicant role");
    const governedResource = input.governedResource ?? defaultGovernedResource(scope);
    if (governedResourceInScope(scope, governedResource.type) !== governedResource.id) {
      throw new Error("Application evidence governed resource is outside the scope");
    }
    this.assertSupportedContractFormat();
    const verifiedAt = this.evidenceTime();
    const expiresAt = new Date(Date.parse(verifiedAt) + 24 * 60 * 60 * 1000).toISOString();
    const envelope = {
      version: "tr-application-evidence-v1" as const,
      registryId: this.registryId,
      applicationId: createScopedIdentifier("application", input.role, input.applicationId),
      subjectDid: input.subjectDid,
      role: input.role,
      policyId: this.policyId,
      policyVersion: this.policyRecord.version,
      scopeCommitment: computeAuthorizationScopeCommitment(scope),
      governedResource,
      evidenceVerifierDid: this.evidenceVerifier.did,
      verifiedAt,
      expiresAt,
      challengeHash: sha256Hex(`challenge:${input.applicationId}`),
      presentationHash: sha256Hex(`presentation:${input.applicationId}`),
      claimsCommitment: sha256Hex(`claims:${input.applicationId}`),
    };
    const commitment = computeApplicationEvidenceCommitment(envelope);
    return {
      envelope,
      commitment,
      signature: this.signApplicationEvidenceCommitment(commitment),
    };
  }

  signApplicationEvidenceCommitment(commitment: string) {
    const keyId = this.evidenceVerifier.keyIds[0]!;
    const signature = signApplicationEvidenceCommitmentFromSeed(
      this.evidenceVerifierKey.seed,
      bytes32Commitment(keyId),
      hashHexToBytes32(commitment),
    );
    return {
      keyId,
      algorithm: "jubjub-schnorr" as const,
      value: `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`,
    };
  }

  verifyApplicationEvidenceSignature(
    commitment: string,
    signature: ApplicationEvidenceSignature,
    verifier: AuthorizedEvidenceVerifier,
  ): boolean {
    if (
      verifier.did !== this.evidenceVerifier.did ||
      signature.keyId !== this.evidenceVerifier.keyIds[0]
    ) return false;
    try {
      // Invalid curve points can trap in the Compact runtime; reject untrusted signatures.
      return verifyApplicationEvidenceCommitmentSignature(
        this.evidenceVerifierPublicKey,
        bytes32Commitment(signature.keyId),
        hashHexToBytes32(commitment),
        decodeCanonicalJubjubSignatureHex(signature.value),
      );
    } catch {
      return false;
    }
  }

  assertApplicationEvidence(input: {
    evidence: ApplicationEvidenceSubmission;
    applicationId: string;
    subjectDid: string;
    role: ApplicationEvidenceRole;
    scope: AuthorizationScope;
    challengeHash?: string;
    governedResource?: GovernedResource;
  }): Uint8Array {
    const scope = AuthorizationScopeSchema.parse(input.scope);
    if (scope.role !== input.role) throw new Error("Application evidence scope role does not match applicant role");
    const governedResource = input.governedResource ?? defaultGovernedResource(scope);
    if (governedResourceInScope(scope, governedResource.type) !== governedResource.id) {
      throw new Error("Application evidence governed resource is outside the scope");
    }
    this.assertSupportedContractFormat();
    const parsed = assertValidApplicationEvidence(
      input.evidence,
      {
        registryId: this.registryId,
        applicationId: createScopedIdentifier("application", input.role, input.applicationId),
        subjectDid: input.subjectDid,
        role: input.role,
        policyId: this.policyId,
        policyVersion: this.policyRecord.version,
        scopeCommitment: computeAuthorizationScopeCommitment(scope),
        governedResource,
        challengeHash: input.challengeHash ?? sha256Hex(`challenge:${input.applicationId}`),
        evaluatedAt: this.evidenceTime(),
      },
      [this.evidenceVerifier],
      (commitment, signature, verifier) => this.verifyApplicationEvidenceSignature(commitment, signature, verifier),
    );
    return hashHexToBytes32(parsed.commitment);
  }

  private buildPolicyRecord(
    defaultThreshold: bigint,
    emergencyThreshold: bigint,
    archivalThreshold: bigint,
    version = 1n,
    effectiveFromSequence = 0n,
  ): GovernancePolicyRecord {
    return GovernancePolicyRecordSchema.parse({
      policyId: this.policyId,
      registryId: this.registryId,
      version: `v${version.toString()}`,
      policyUri: `https://registry.example/policies/kanon-v${version.toString()}`,
      status: "active",
      effectiveFrom: timestampForSequence(effectiveFromSequence),
      policyTemplates: [
        {
          templateId: createScopedIdentifier("policy-template", "maintainer", "v1"),
          family: "maintainer",
          name: "Maintainer Governance",
          description: "Maintainer onboarding and membership changes",
          requiredMaintainerThreshold: thresholdToPolicyNumber(defaultThreshold),
          applicableRoles: ["maintainer"],
          applicableActionKinds: [
            "tr:maintainer:propose",
            "tr:maintainer:authorize",
            "tr:maintainer:activate",
            "tr:policy:thresholds:update",
          ],
          evidenceRules: ["governance evidence hash", "maintainer quorum signatures"],
        },
        {
          templateId: createScopedIdentifier("policy-template", "member", "v1"),
          family: "member",
          name: "Member Governance",
          description: "Issuer, verifier, and recognition onboarding decisions",
          requiredMaintainerThreshold: thresholdToPolicyNumber(defaultThreshold),
          applicableRoles: ["issuer", "verifier", "authority"],
          applicableActionKinds: [
            "tr:issuer:propose",
            "tr:issuer:authorize",
            "tr:issuer:activate",
            "tr:evidence-verifier:register",
            "tr:evidence-verifier:rotate",
            "tr:verifier:propose",
            "tr:verifier:authorize",
            "tr:verifier:activate",
            "tr:recognition:propose",
            "tr:recognition:authorize",
            "tr:recognition:activate",
          ],
          evidenceRules: ["application evidence", "maintainer quorum signatures"],
        },
        {
          templateId: createScopedIdentifier("policy-template", "emergency", "v1"),
          family: "emergency",
          name: "Emergency Governance",
          description: "Emergency suspension and revocation decisions",
          requiredMaintainerThreshold: thresholdToPolicyNumber(emergencyThreshold),
          applicableRoles: ["issuer", "verifier", "maintainer", "authority", "auditor"],
          applicableActionKinds: [
            "tr:issuer:suspend",
            "tr:issuer:revoke",
            "tr:evidence-verifier:suspend",
            "tr:evidence-verifier:revoke",
            "tr:verifier:suspend",
            "tr:verifier:revoke",
            "tr:maintainer:suspend",
            "tr:maintainer:revoke",
            "tr:recognition:suspend",
            "tr:recognition:revoke",
            "tr:auditor:suspend",
            "tr:auditor:revoke",
          ],
          evidenceRules: ["incident evidence", "maintainer quorum signatures"],
        },
        {
          templateId: createScopedIdentifier("policy-template", "archival", "v1"),
          family: "archival",
          name: "Archival Governance",
          description: "Historical archival and closure decisions",
          requiredMaintainerThreshold: thresholdToPolicyNumber(archivalThreshold),
          applicableRoles: ["issuer", "verifier", "maintainer", "authority", "auditor"],
          applicableActionKinds: [
            "tr:issuer:archive",
            "tr:verifier:archive",
            "tr:maintainer:archive",
            "tr:recognition:archive",
            "tr:auditor:archive",
          ],
          evidenceRules: ["archival justification", "maintainer quorum signatures"],
        },
        {
          templateId: createScopedIdentifier("policy-template", "auditor", "v1"),
          family: "auditor",
          name: "Auditor Governance",
          description: "Auditor onboarding and oversight decisions",
          requiredMaintainerThreshold: thresholdToPolicyNumber(defaultThreshold),
          applicableRoles: ["auditor"],
          applicableActionKinds: [
            "tr:auditor:propose",
            "tr:auditor:authorize",
            "tr:auditor:activate",
          ],
          evidenceRules: ["audit mandate evidence", "maintainer quorum signatures"],
        },
      ],
      decisionBindings: [
        {
          bindingId: createScopedIdentifier("policy-binding", "maintainer", "v1"),
          family: "maintainer",
          templateId: createScopedIdentifier("policy-template", "maintainer", "v1"),
          actionScopes: ["maintainer-membership", "threshold-policy"],
        },
        {
          bindingId: createScopedIdentifier("policy-binding", "member", "v1"),
          family: "member",
          templateId: createScopedIdentifier("policy-template", "member", "v1"),
          actionScopes: ["issuer-authorization", "verifier-authorization", "recognition"],
        },
        {
          bindingId: createScopedIdentifier("policy-binding", "emergency", "v1"),
          family: "emergency",
          templateId: createScopedIdentifier("policy-template", "emergency", "v1"),
          actionScopes: ["participant-emergency"],
        },
        {
          bindingId: createScopedIdentifier("policy-binding", "archival", "v1"),
          family: "archival",
          templateId: createScopedIdentifier("policy-template", "archival", "v1"),
          actionScopes: ["participant-archival"],
        },
        {
          bindingId: createScopedIdentifier("policy-binding", "auditor", "v1"),
          family: "auditor",
          templateId: createScopedIdentifier("policy-template", "auditor", "v1"),
          actionScopes: ["auditor-authorization"],
        },
      ],
      decisionRules: [
        `member governance starts at ${defaultThreshold.toString()}-of-active-maintainers`,
        "maintainer threshold policy may raise default, emergency, and archival quorum after additional maintainers activate",
      ],
      disputeRules: ["manual operator review"],
      retentionRules: ["retain historical trust evidence for long-term verification"],
      emergencyRules: [
        `emergency governance requires ${emergencyThreshold.toString()} approving maintainers`,
      ],
      lifecycleEventRoot: sha256Hex(this.policyId),
    });
  }

  private bootstrapActionSignature(
    actionKind: Uint8Array,
    actionPayloadHash: Uint8Array,
    actionSequence: bigint,
  ) {
    return this.signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );
  }

  private signMaintainerActionFromSeed(
    seed: Uint8Array,
    registryId: Uint8Array,
    actionKind: Uint8Array,
    actionPayloadHash: Uint8Array,
    actionSequence: bigint,
  ) {
    return signPolicyBoundMaintainerActionFromSeed(
      seed,
      registryId,
      this.simulator.getLedger().governancePolicyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );
  }

  private maintainerCoAuthorizers(
    maintainers: readonly MaintainerScenarioFixture[],
    actionKind: Uint8Array,
    actionPayloadHash: Uint8Array,
    actionSequence: bigint,
  ): MaintainerCoAuthorizer[] {
    return maintainers.map((maintainer) => ({
      keyId: maintainer.keyId,
      publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
      signature: this.signMaintainerActionFromSeed(
        maintainer.seed,
        this.registryIdCommitment,
        actionKind,
        actionPayloadHash,
        actionSequence,
      ),
    }));
  }

  private activeDefaultQuorumCoMaintainers(): MaintainerScenarioFixture[] {
    const requiredCoMaintainers = Number(
      this.simulator.getLedger().maintainerThreshold - 1n,
    );
    if (requiredCoMaintainers <= 0) {
      return [];
    }

    const activeCoMaintainers = [...this.knownMaintainers.values()].filter(
      (maintainer) => {
        if (
          sameBytes(
            maintainer.maintainerIdCommitment,
            this.maintainerIdCommitment,
          )
        ) {
          return false;
        }

        return (
          this.simulator.getMaintainerMembership(maintainer.maintainerIdCommitment)
            .status === ContractAuthorizationStatus.active
        );
      },
    );
    activeCoMaintainers.sort((left, right) =>
      bytes32Hex(left.keyId).localeCompare(bytes32Hex(right.keyId)),
    );

    if (activeCoMaintainers.length < requiredCoMaintainers) {
      throw new Error(
        "insufficient active co-maintainers to satisfy the default quorum threshold",
      );
    }

    return activeCoMaintainers.slice(0, requiredCoMaintainers);
  }

  updateMaintainerThresholdPolicy(
    defaultThreshold: bigint,
    emergencyThreshold: bigint,
    archivalThreshold: bigint,
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
  ): Uint8Array {
    const prepared = this.prepareThresholdPolicyRevisionAction(
      defaultThreshold, emergencyThreshold, archivalThreshold,
    );
    const result = this.executeThresholdPolicyRevisionWithSignatures(
      defaultThreshold, emergencyThreshold, archivalThreshold,
      [{
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      }, ...this.maintainerCoAuthorizers(
        additionalMaintainers, prepared.actionKind, prepared.actionPayloadHash,
        prepared.actionSequence,
      )],
    );
    this.authorizeEvidenceVerifierForCurrentPolicy();
    return result;
  }

  prepareThresholdPolicyRevisionAction(
    defaultThreshold: bigint,
    emergencyThreshold: bigint,
    archivalThreshold: bigint,
  ): PreparedThresholdPolicyRevisionAction {
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const nextPolicyVersion = this.simulator.getLedger().governancePolicyVersion + 1n;
    const nextPolicyRecord = this.buildPolicyRecord(
      defaultThreshold,
      emergencyThreshold,
      archivalThreshold,
      nextPolicyVersion,
      actionSequence + 1n,
    );
    assertGovernancePolicyRevision(
      deriveGovernancePolicySnapshot(this.policyRecordValue),
      deriveGovernancePolicySnapshot(nextPolicyRecord),
    );
    const nextPolicyCommitment = hashHexToBytes32(
      computeGovernancePolicySnapshotCommitment(
        deriveGovernancePolicySnapshot(nextPolicyRecord),
      ),
    );
    const actionPayloadHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      this.governancePolicyCommitment,
      nextPolicyCommitment,
      nextPolicyVersion,
      defaultThreshold,
      emergencyThreshold,
      archivalThreshold,
    );
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      policyCommitment: Uint8Array.from(this.governancePolicyCommitment),
      actionKind: Uint8Array.from(UPDATE_MAINTAINER_THRESHOLD_POLICY_ACTION_KIND),
      actionPayloadHash,
      actionSequence,
      nextPolicyCommitment,
      nextPolicyVersion,
    };
  }

  /** Compact checks current policy, sequence, distinct active keys, signatures, and quorum. */
  executeThresholdPolicyRevisionWithSignatures(
    defaultThreshold: bigint,
    emergencyThreshold: bigint,
    archivalThreshold: bigint,
    signers: readonly MaintainerCoAuthorizer[],
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Threshold revision requires a maintainer signature");
    const prepared = this.prepareThresholdPolicyRevisionAction(
      defaultThreshold, emergencyThreshold, archivalThreshold,
    );
    const nextPolicyRecord = this.buildPolicyRecord(
      defaultThreshold, emergencyThreshold, archivalThreshold,
      prepared.nextPolicyVersion, prepared.actionSequence + 1n,
    );
    const result = this.simulator.updateMaintainerThresholdPolicy(
      primary.keyId, primary.publicKey, primary.signature,
      prepared.nextPolicyCommitment, prepared.nextPolicyVersion,
      defaultThreshold, emergencyThreshold, archivalThreshold,
      signers.slice(1),
    );
    this.policyRecordValue = nextPolicyRecord;
    this.governancePolicyCommitment = prepared.nextPolicyCommitment;
    this.registryRecord = RegistryRecordSchema.parse({
      ...this.registryRecord,
      policyUri: nextPolicyRecord.policyUri,
      updatedAt: timestampForSequence(prepared.actionSequence),
      lifecycleEventRoot: bytes32Hex(result),
    });
    this.policyRevisions.push({
      effectiveFromSequence: prepared.actionSequence + 1n,
      commitment: prepared.nextPolicyCommitment,
      record: nextPolicyRecord,
    });
    return result;
  }

  authorizeMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    this.proposeMaintainer(fixture);
    this.approveMaintainer(fixture);
    return this.activateMaintainer(fixture);
  }

  proposeMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    return this.proposeMaintainerWithApplicationEvidence(
      fixture,
      this.createApplicationEvidence({
        applicationId: fixture.maintainerId,
        subjectDid: fixture.subjectDid,
        role: "maintainer",
        scope: createMaintainerAuthorizationScopeFixture(this.registryId),
      }),
    );
  }

  proposeMaintainerWithApplicationEvidence(
    fixture: MaintainerScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createMaintainerAuthorizationScopeFixture(this.registryId),
      challengeHash: sha256Hex(`challenge:${fixture.maintainerId}`),
      governedResource: { type: "registry", id: this.registryId },
    },
  ): Uint8Array {
    const prepared = this.prepareMaintainerProposalAction(fixture, evidence, expectedEvidence);
    return this.executeMaintainerProposalWithSignatures(fixture, evidence, [
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
      ),
    ], this.signMaintainerProposalEvidence(prepared), expectedEvidence);
  }

  prepareMaintainerProposalAction(
    fixture: MaintainerScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createMaintainerAuthorizationScopeFixture(this.registryId),
      challengeHash: sha256Hex(`challenge:${fixture.maintainerId}`),
      governedResource: { type: "registry", id: this.registryId },
    },
  ): PreparedMaintainerProposalAction {
    if (
      expectedEvidence.scope.role !== "maintainer" ||
      expectedEvidence.scope.registryId !== this.registryId ||
      expectedEvidence.governedResource.type !== "registry" ||
      expectedEvidence.governedResource.id !== this.registryId
    ) {
      throw new Error("Maintainer proposal scope does not match governed registry");
    }
    const candidatePublicKey = deriveJubjubPublicKeyFromSeed(fixture.seed);
    const proposedEvidenceHash = this.assertApplicationEvidence({
      evidence,
      applicationId: fixture.maintainerId,
      subjectDid: fixture.subjectDid,
      role: "maintainer",
      ...expectedEvidence,
    });
    const ledger = this.simulator.getLedger();
    const baseMaintainerPayloadHash = computeCreateMaintainerMembershipPayloadHash(
      fixture.maintainerIdCommitment,
      fixture.subjectDidCommitment,
      fixture.keyId,
      candidatePublicKey,
      ledger.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      maintainerId: Uint8Array.from(fixture.maintainerIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      policyVersion: ledger.governancePolicyVersion,
      actionKind: Uint8Array.from(PROPOSE_MAINTAINER_ACTION_KIND),
      actionPayloadHash: computeMaintainerEvidenceBoundProposalPayloadHash(
        baseMaintainerPayloadHash,
        this.currentEvidenceVerifierAuthorizationId,
        this.currentEvidenceVerifierKeyIdCommitment,
        ledger.governancePolicyCommitment,
        ledger.governancePolicyVersion,
      ),
      actionSequence: ledger.governanceActionCount,
      evidenceHash: Uint8Array.from(proposedEvidenceHash),
      evidenceVerifierAuthorizationId: Uint8Array.from(this.currentEvidenceVerifierAuthorizationId),
      evidenceVerifierKeyIdCommitment: Uint8Array.from(this.currentEvidenceVerifierKeyIdCommitment),
    };
  }

  signMaintainerProposalEvidence(prepared: PreparedMaintainerProposalAction): TrustRegistryJubjubSignature {
    return signMaintainerProposalEvidenceFromSeed(
      this.evidenceVerifierKey.seed,
      prepared.registryId,
      prepared.evidenceVerifierKeyIdCommitment,
      prepared.actionPayloadHash,
    );
  }

  executeMaintainerProposalWithSignatures(
    fixture: MaintainerScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    signers: readonly MaintainerCoAuthorizer[],
    verifierSignature: TrustRegistryJubjubSignature,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createMaintainerAuthorizationScopeFixture(this.registryId),
      challengeHash: sha256Hex(`challenge:${fixture.maintainerId}`),
      governedResource: { type: "registry", id: this.registryId },
    },
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Maintainer proposal requires a maintainer signature");
    const prepared = this.prepareMaintainerProposalAction(fixture, evidence, expectedEvidence);
    const candidatePublicKey = deriveJubjubPublicKeyFromSeed(fixture.seed);

    return this.simulator.proposeMaintainerMembership(
      primary.keyId,
      primary.publicKey,
      primary.signature,
      fixture.maintainerIdCommitment,
      fixture.subjectDidCommitment,
      fixture.keyId,
      candidatePublicKey,
      prepared.policyCommitment,
      bytes32Commitment(fixture.trustLevel),
      prepared.evidenceHash,
      prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment,
      verifierSignature,
      signers.slice(1),
    );
  }

  prepareMaintainerDecisionAction(
    fixture: MaintainerScenarioFixture,
    action: IssuerDecisionAction,
  ): PreparedMaintainerAction {
    if (!["approve", "activate", "suspend", "revoke"].includes(action)) {
      throw new Error("Unsupported maintainer decision action");
    }
    const current = this.simulator.getMaintainerMembership(fixture.maintainerIdCommitment);
    const ledger = this.simulator.getLedger();
    const evidenceHash = action === "approve" || action === "activate"
      ? current.evidenceHash : bytes32Commitment(`${fixture.maintainerId}:${action}`);
    const actionKinds = {
      approve: AUTHORIZE_MAINTAINER_ACTION_KIND,
      activate: ACTIVATE_MAINTAINER_ACTION_KIND,
      suspend: SUSPEND_MAINTAINER_ACTION_KIND,
      revoke: REVOKE_MAINTAINER_ACTION_KIND,
    };
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      maintainerId: Uint8Array.from(fixture.maintainerIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      actionKind: Uint8Array.from(actionKinds[action]),
      actionPayloadHash: computeUpdateMaintainerMembershipPayloadHash(
        fixture.maintainerIdCommitment, current.lifecycleEventHash, evidenceHash,
      ),
      actionSequence: ledger.governanceActionCount,
      previousLifecycleEventHash: Uint8Array.from(current.lifecycleEventHash),
      evidenceHash: Uint8Array.from(evidenceHash),
    };
  }

  executeMaintainerDecisionWithSignatures(
    fixture: MaintainerScenarioFixture,
    action: IssuerDecisionAction,
    signers: readonly MaintainerCoAuthorizer[],
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Maintainer decision requires a maintainer signature");
    const prepared = this.prepareMaintainerDecisionAction(fixture, action);
    if (action === "approve") {
      return this.simulator.authorizeMaintainerMembership(
        primary.keyId, primary.publicKey, primary.signature,
        fixture.maintainerIdCommitment, prepared.evidenceHash, signers.slice(1),
      );
    }
    const circuit = action === "activate" ? this.simulator.activateMaintainerMembership.bind(this.simulator)
      : action === "suspend" ? this.simulator.suspendMaintainerMembership.bind(this.simulator)
        : this.simulator.revokeMaintainerMembership.bind(this.simulator);
    const result = circuit(primary.keyId, primary.publicKey, primary.signature,
      fixture.maintainerIdCommitment, prepared.evidenceHash, signers.slice(1));
    if (action === "activate") this.knownMaintainers.set(bytes32Hex(fixture.maintainerIdCommitment), fixture);
    return result;
  }

  private fixtureMaintainerDecision(fixture: MaintainerScenarioFixture, action: IssuerDecisionAction): Uint8Array {
    const prepared = this.prepareMaintainerDecisionAction(fixture, action);
    return this.executeMaintainerDecisionWithSignatures(fixture, action, [
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
      ),
    ]);
  }

  approveMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    return this.fixtureMaintainerDecision(fixture, "approve");
  }

  activateMaintainer(fixture: MaintainerScenarioFixture): Uint8Array {
    return this.fixtureMaintainerDecision(fixture, "activate");
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

  proposeIssuer(
    fixture: IssuerScenarioFixture,
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
  ): Uint8Array {
    return this.proposeIssuerWithApplicationEvidence(
      fixture,
      this.createApplicationEvidence({
        applicationId: fixture.authorizationId,
        subjectDid: fixture.subjectDid,
        role: "issuer",
        scope: createIssuerAuthorizationScopeFixture(fixture),
        governedResource: issuerGovernedResource(fixture),
      }),
      additionalMaintainers,
    );
  }

  proposeIssuerWithApplicationEvidence(
    fixture: IssuerScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
    expectedEvidence: SimulatorApplicationEvidenceExpectation = defaultIssuerEvidenceExpectation(fixture),
  ): Uint8Array {
    const prepared = this.prepareIssuerProposalAction(fixture, evidence, expectedEvidence);
    return this.executeIssuerProposalWithSignatures(
      fixture,
      evidence,
      [
        {
          keyId: this.bootstrapMaintainer.keyId,
          publicKey: this.bootstrapPublicKey,
          signature: this.bootstrapActionSignature(
            prepared.actionKind,
            prepared.actionPayloadHash,
            prepared.actionSequence,
          ),
        },
        ...this.maintainerCoAuthorizers(
          additionalMaintainers,
          prepared.actionKind,
          prepared.actionPayloadHash,
          prepared.actionSequence,
        ),
      ],
      signIssuerProposalEvidenceFromSeed(
        this.evidenceVerifierKey.seed,
        prepared.registryId,
        prepared.evidenceVerifierKeyIdCommitment,
        prepared.actionPayloadHash,
      ),
      expectedEvidence,
    );
  }

  prepareIssuerProposalAction(
    fixture: IssuerScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = defaultIssuerEvidenceExpectation(fixture),
  ): PreparedIssuerProposalAction {
    if (
      expectedEvidence.scope.role !== "issuer" ||
      expectedEvidence.governedResource.type !== issuerGovernedResource(fixture).type ||
      expectedEvidence.governedResource.id !== fixture.resourceId ||
      governedResourceInScope(expectedEvidence.scope, expectedEvidence.governedResource.type) !== fixture.resourceId ||
      computeAuthorizationScopeCommitment(expectedEvidence.scope) !==
        computeAuthorizationScopeCommitment(createIssuerAuthorizationScopeFixture(fixture))
    ) {
      throw new Error("Issuer proposal scope does not match governed resource");
    }
    const proposedEvidenceHash = this.assertApplicationEvidence({
      evidence,
      applicationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      role: "issuer",
      ...expectedEvidence,
    });
    const statusPolicyBindingCommitment = hashHexToBytes32(
      computeIssuerStatusPolicyBindingCommitment(this.issuerStatusPolicyBinding(fixture)),
    );
    const ledger = this.simulator.getLedger();
    const baseIssuerPayloadHash = computeCreateIssuerAuthorizationPayloadHash(
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.resourceType,
      fixture.resourceIdCommitment,
      ledger.governancePolicyCommitment,
      statusPolicyBindingCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
    const actionPayloadHash = computeIssuerEvidenceBoundProposalPayloadHash(
      baseIssuerPayloadHash,
      this.currentEvidenceVerifierAuthorizationId,
      this.currentEvidenceVerifierKeyIdCommitment,
      ledger.governancePolicyCommitment,
      ledger.governancePolicyVersion,
    );
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      authorizationId: Uint8Array.from(fixture.authorizationIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      policyVersion: ledger.governancePolicyVersion,
      actionKind: Uint8Array.from(PROPOSE_ISSUER_ACTION_KIND),
      actionPayloadHash,
      actionSequence: ledger.governanceActionCount,
      evidenceHash: Uint8Array.from(proposedEvidenceHash),
      statusPolicyBindingCommitment,
      evidenceVerifierAuthorizationId: Uint8Array.from(this.currentEvidenceVerifierAuthorizationId),
      evidenceVerifierKeyIdCommitment: Uint8Array.from(this.currentEvidenceVerifierKeyIdCommitment),
    };
  }

  signIssuerProposalEvidence(prepared: PreparedIssuerProposalAction): TrustRegistryJubjubSignature {
    return signIssuerProposalEvidenceFromSeed(
      this.evidenceVerifierKey.seed,
      prepared.registryId,
      prepared.evidenceVerifierKeyIdCommitment,
      prepared.actionPayloadHash,
    );
  }

  executeIssuerProposalWithSignatures(
    fixture: IssuerScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    signers: readonly MaintainerCoAuthorizer[],
    verifierSignature: TrustRegistryJubjubSignature,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = defaultIssuerEvidenceExpectation(fixture),
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Issuer proposal requires a maintainer signature");
    const prepared = this.prepareIssuerProposalAction(fixture, evidence, expectedEvidence);
    const eventHash = this.simulator.proposeIssuerAuthorization(
      primary.keyId,
      primary.publicKey,
      primary.signature,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.resourceType,
      fixture.resourceIdCommitment,
      prepared.policyCommitment,
      prepared.statusPolicyBindingCommitment,
      bytes32Commitment(fixture.trustLevel),
      prepared.evidenceHash,
      prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment,
      verifierSignature,
      signers.slice(1),
    );
    this.issuerApplicationEvidence.set(fixture.authorizationId, {
      evidence,
      challengeHash: expectedEvidence.challengeHash,
    });
    return eventHash;
  }

  private recheckIssuerApplicationEvidence(fixture: IssuerScenarioFixture): void {
    const accepted = this.issuerApplicationEvidence.get(fixture.authorizationId);
    if (accepted === undefined) {
      throw new Error("Issuer application evidence is unavailable for approval or activation");
    }
    const commitment = this.assertApplicationEvidence({
      evidence: accepted.evidence,
      applicationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(fixture),
      challengeHash: accepted.challengeHash,
      governedResource: issuerGovernedResource(fixture),
    });
    const proposal = this.simulator.getIssuerProposalEvidence(fixture.authorizationIdCommitment);
    if (!Buffer.from(commitment).equals(Buffer.from(proposal.evidenceCommitment))) {
      throw new Error("Issuer application evidence no longer matches the governed proposal");
    }
  }

  prepareIssuerDecisionAction(
    fixture: IssuerScenarioFixture,
    action: IssuerDecisionAction,
  ): PreparedIssuerDecisionAction {
    if (!["approve", "activate", "suspend", "revoke"].includes(action)) {
      throw new Error("Unsupported issuer decision action");
    }
    if (action === "approve" || action === "activate") this.recheckIssuerApplicationEvidence(fixture);
    const ledger = this.simulator.getLedger();
    const current = this.simulator.getIssuerAuthorization(fixture.authorizationIdCommitment);
    const evidenceHash = action === "approve" || action === "activate"
      ? current.evidenceHash : bytes32Commitment(`${fixture.authorizationId}:${action}`);
    const actionKinds = {
      approve: AUTHORIZE_ISSUER_ACTION_KIND,
      activate: ACTIVATE_ISSUER_ACTION_KIND,
      suspend: SUSPEND_ISSUER_ACTION_KIND,
      revoke: REVOKE_ISSUER_ACTION_KIND,
    };
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      authorizationId: Uint8Array.from(fixture.authorizationIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      actionKind: Uint8Array.from(actionKinds[action]),
      actionPayloadHash: computeUpdateIssuerAuthorizationPayloadHash(
        fixture.authorizationIdCommitment,
        current.lifecycleEventHash,
        evidenceHash,
      ),
      actionSequence: ledger.governanceActionCount,
      previousLifecycleEventHash: Uint8Array.from(current.lifecycleEventHash),
      evidenceHash: Uint8Array.from(evidenceHash),
    };
  }

  /** The Compact simulator verifies current context, active signer membership, and quorum. */
  executeIssuerDecisionWithSignatures(
    fixture: IssuerScenarioFixture,
    action: IssuerDecisionAction,
    signers: readonly MaintainerCoAuthorizer[],
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Issuer decision requires a maintainer signature");
    const prepared = this.prepareIssuerDecisionAction(fixture, action);
    if (action === "approve") {
      return this.simulator.authorizeIssuerAuthorization(
        primary.keyId,
        primary.publicKey,
        primary.signature,
        fixture.authorizationIdCommitment,
        prepared.evidenceHash,
        signers.slice(1),
      );
    }
    const circuit = action === "activate" ? this.simulator.activateIssuerAuthorization.bind(this.simulator)
      : action === "suspend" ? this.simulator.suspendIssuerAuthorization.bind(this.simulator)
        : this.simulator.revokeIssuerAuthorization.bind(this.simulator);
    return circuit(primary.keyId, primary.publicKey, primary.signature,
      fixture.authorizationIdCommitment, prepared.evidenceHash, signers.slice(1));
  }

  approveIssuer(
    fixture: IssuerScenarioFixture,
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
  ): Uint8Array {
    this.recheckIssuerApplicationEvidence(fixture);
    const authorizedEvidenceHash = this.simulator.getIssuerAuthorization(
      fixture.authorizationIdCommitment,
    ).evidenceHash;
    const authorizeActionSequence = this.simulator.getLedger().governanceActionCount;
    const actionPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      fixture.authorizationIdCommitment,
      this.simulator.getIssuerAuthorization(fixture.authorizationIdCommitment)
        .lifecycleEventHash,
      authorizedEvidenceHash,
    );
    return this.simulator.authorizeIssuerAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      this.bootstrapActionSignature(
        AUTHORIZE_ISSUER_ACTION_KIND,
        actionPayloadHash,
        authorizeActionSequence,
      ),
      fixture.authorizationIdCommitment,
      authorizedEvidenceHash,
      this.maintainerCoAuthorizers(
        additionalMaintainers,
        AUTHORIZE_ISSUER_ACTION_KIND,
        actionPayloadHash,
        authorizeActionSequence,
      ),
    );
  }

  activateIssuer(
    fixture: IssuerScenarioFixture,
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
  ): Uint8Array {
    this.recheckIssuerApplicationEvidence(fixture);
    const evidenceHash = this.simulator.getIssuerAuthorization(
      fixture.authorizationIdCommitment,
    ).evidenceHash;
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const actionPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      fixture.authorizationIdCommitment,
      this.simulator.getIssuerAuthorization(fixture.authorizationIdCommitment)
        .lifecycleEventHash,
      evidenceHash,
    );

    return this.simulator.activateIssuerAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      this.bootstrapActionSignature(
        ACTIVATE_ISSUER_ACTION_KIND,
        actionPayloadHash,
        actionSequence,
      ),
      fixture.authorizationIdCommitment,
      evidenceHash,
      this.maintainerCoAuthorizers(
        additionalMaintainers,
        ACTIVATE_ISSUER_ACTION_KIND,
        actionPayloadHash,
        actionSequence,
      ),
    );
  }

  suspendIssuer(
    fixture: IssuerScenarioFixture,
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
  ): Uint8Array {
    return this.updateIssuerLifecycle(
      fixture,
      "suspend",
      SUSPEND_ISSUER_ACTION_KIND,
      additionalMaintainers,
    );
  }

  revokeIssuer(
    fixture: IssuerScenarioFixture,
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
  ): Uint8Array {
    return this.updateIssuerLifecycle(
      fixture,
      "revoke",
      REVOKE_ISSUER_ACTION_KIND,
      additionalMaintainers,
    );
  }

  archiveIssuer(
    fixture: IssuerScenarioFixture,
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
  ): Uint8Array {
    return this.updateIssuerLifecycle(
      fixture,
      "archive",
      ARCHIVE_ISSUER_ACTION_KIND,
      additionalMaintainers,
    );
  }

  proposeVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    return this.proposeVerifierWithApplicationEvidence(
      fixture,
      this.createApplicationEvidence({
        applicationId: fixture.authorizationId,
        subjectDid: fixture.subjectDid,
        role: "verifier",
        scope: createVerifierAuthorizationScopeFixture(fixture),
      }),
    );
  }

  proposeVerifierWithApplicationEvidence(
    fixture: VerifierScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createVerifierAuthorizationScopeFixture(fixture),
      challengeHash: sha256Hex(`challenge:${fixture.authorizationId}`),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId },
    },
  ): Uint8Array {
    const prepared = this.prepareVerifierProposalAction(fixture, evidence, expectedEvidence);
    return this.executeVerifierProposalWithSignatures(fixture, evidence, [
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind,
        prepared.actionPayloadHash,
        prepared.actionSequence,
      ),
    ], this.signVerifierProposalEvidence(prepared), expectedEvidence);
  }

  prepareVerifierProposalAction(
    fixture: VerifierScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createVerifierAuthorizationScopeFixture(fixture),
      challengeHash: sha256Hex(`challenge:${fixture.authorizationId}`),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId },
    },
  ): PreparedVerifierProposalAction {
    if (
      expectedEvidence.scope.role !== "verifier" ||
      expectedEvidence.governedResource.type !== "requestProfile" ||
      expectedEvidence.governedResource.id !== fixture.scopeResourceId ||
      computeAuthorizationScopeCommitment(expectedEvidence.scope) !==
        computeAuthorizationScopeCommitment(createVerifierAuthorizationScopeFixture(fixture))
    ) {
      throw new Error("Verifier proposal scope does not match governed request profile");
    }
    const proposedEvidenceHash = this.assertApplicationEvidence({
      evidence,
      applicationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      role: "verifier",
      ...expectedEvidence,
    });
    const ledger = this.simulator.getLedger();
    const baseVerifierPayloadHash = computeCreateVerifierAuthorizationPayloadHash(
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.requestResourceIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
      ledger.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      authorizationId: Uint8Array.from(fixture.authorizationIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      policyVersion: ledger.governancePolicyVersion,
      actionKind: Uint8Array.from(PROPOSE_VERIFIER_ACTION_KIND),
      actionPayloadHash: computeVerifierEvidenceBoundProposalPayloadHash(
        baseVerifierPayloadHash,
        this.currentEvidenceVerifierAuthorizationId,
        this.currentEvidenceVerifierKeyIdCommitment,
        ledger.governancePolicyCommitment,
        ledger.governancePolicyVersion,
      ),
      actionSequence: ledger.governanceActionCount,
      evidenceHash: Uint8Array.from(proposedEvidenceHash),
      evidenceVerifierAuthorizationId: Uint8Array.from(this.currentEvidenceVerifierAuthorizationId),
      evidenceVerifierKeyIdCommitment: Uint8Array.from(this.currentEvidenceVerifierKeyIdCommitment),
    };
  }

  signVerifierProposalEvidence(prepared: PreparedVerifierProposalAction): TrustRegistryJubjubSignature {
    return signVerifierProposalEvidenceFromSeed(
      this.evidenceVerifierKey.seed,
      prepared.registryId,
      prepared.evidenceVerifierKeyIdCommitment,
      prepared.actionPayloadHash,
    );
  }

  executeVerifierProposalWithSignatures(
    fixture: VerifierScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    signers: readonly MaintainerCoAuthorizer[],
    verifierSignature: TrustRegistryJubjubSignature,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createVerifierAuthorizationScopeFixture(fixture),
      challengeHash: sha256Hex(`challenge:${fixture.authorizationId}`),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId },
    },
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Verifier proposal requires a maintainer signature");
    const prepared = this.prepareVerifierProposalAction(fixture, evidence, expectedEvidence);
    return this.simulator.proposeVerifierAuthorization(
      primary.keyId,
      primary.publicKey,
      primary.signature,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.requestResourceIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
      prepared.policyCommitment,
      bytes32Commitment(fixture.trustLevel),
      prepared.evidenceHash,
      prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment,
      verifierSignature,
      signers.slice(1),
    );
  }

  prepareVerifierDecisionAction(
    fixture: VerifierScenarioFixture,
    action: IssuerDecisionAction,
  ): PreparedIssuerDecisionAction {
    if (!["approve", "activate", "suspend", "revoke"].includes(action)) {
      throw new Error("Unsupported verifier decision action");
    }
    const current = this.simulator.getVerifierAuthorization(fixture.authorizationIdCommitment);
    const ledger = this.simulator.getLedger();
    const evidenceHash = action === "approve" || action === "activate"
      ? current.evidenceHash : bytes32Commitment(`${fixture.authorizationId}:${action}`);
    const actionKinds = {
      approve: AUTHORIZE_VERIFIER_ACTION_KIND,
      activate: ACTIVATE_VERIFIER_ACTION_KIND,
      suspend: SUSPEND_VERIFIER_ACTION_KIND,
      revoke: REVOKE_VERIFIER_ACTION_KIND,
    };
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      authorizationId: Uint8Array.from(fixture.authorizationIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      actionKind: Uint8Array.from(actionKinds[action]),
      actionPayloadHash: computeUpdateVerifierAuthorizationPayloadHash(
        fixture.authorizationIdCommitment, current.lifecycleEventHash, evidenceHash,
      ),
      actionSequence: ledger.governanceActionCount,
      previousLifecycleEventHash: Uint8Array.from(current.lifecycleEventHash),
      evidenceHash: Uint8Array.from(evidenceHash),
    };
  }

  executeVerifierDecisionWithSignatures(
    fixture: VerifierScenarioFixture,
    action: IssuerDecisionAction,
    signers: readonly MaintainerCoAuthorizer[],
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Verifier decision requires a maintainer signature");
    const prepared = this.prepareVerifierDecisionAction(fixture, action);
    if (action === "approve") {
      return this.simulator.authorizeVerifierAuthorization(
        primary.keyId, primary.publicKey, primary.signature,
        fixture.authorizationIdCommitment, prepared.evidenceHash, signers.slice(1),
      );
    }
    const circuit = action === "activate" ? this.simulator.activateVerifierAuthorization.bind(this.simulator)
      : action === "suspend" ? this.simulator.suspendVerifierAuthorization.bind(this.simulator)
        : this.simulator.revokeVerifierAuthorization.bind(this.simulator);
    return circuit(primary.keyId, primary.publicKey, primary.signature,
      fixture.authorizationIdCommitment, prepared.evidenceHash, signers.slice(1));
  }

  private fixtureVerifierDecision(fixture: VerifierScenarioFixture, action: IssuerDecisionAction): Uint8Array {
    const prepared = this.prepareVerifierDecisionAction(fixture, action);
    return this.executeVerifierDecisionWithSignatures(fixture, action, [
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind,
        prepared.actionPayloadHash,
        prepared.actionSequence,
      ),
    ]);
  }

  approveVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    return this.fixtureVerifierDecision(fixture, "approve");
  }

  activateVerifier(fixture: VerifierScenarioFixture): Uint8Array {
    return this.fixtureVerifierDecision(fixture, "activate");
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
    const prepared = this.prepareRecognitionProposalAction(fixture);
    return this.executeRecognitionProposalWithSignatures(fixture, [
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
      ),
    ]);
  }

  prepareRecognitionProposalAction(fixture: RecognitionScenarioFixture): PreparedRecognitionAction {
    const proposedEvidenceHash = bytes32Commitment(
      `${fixture.recognitionId}:propose`,
    );
    const ledger = this.simulator.getLedger();
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      recognitionId: Uint8Array.from(fixture.recognitionIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      actionKind: Uint8Array.from(PROPOSE_RECOGNITION_ACTION_KIND),
      actionPayloadHash: computeCreateRecognitionPayloadHash(
        fixture.recognitionIdCommitment,
        fixture.recognizedAuthorityDidCommitment,
        fixture.recognizedRegistryIdCommitment,
        fixture.scopeResourceTypeCommitment,
        fixture.scopeResourceIdCommitment,
        ledger.governancePolicyCommitment,
        bytes32Commitment(fixture.trustLevel),
        proposedEvidenceHash,
      ),
      actionSequence: ledger.governanceActionCount,
      evidenceHash: Uint8Array.from(proposedEvidenceHash),
    };
  }

  executeRecognitionProposalWithSignatures(
    fixture: RecognitionScenarioFixture,
    signers: readonly MaintainerCoAuthorizer[],
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Recognition proposal requires a maintainer signature");
    const prepared = this.prepareRecognitionProposalAction(fixture);

    return this.simulator.proposeRecognition(
      primary.keyId,
      primary.publicKey,
      primary.signature,
      fixture.recognitionIdCommitment,
      fixture.recognizedAuthorityDidCommitment,
      fixture.recognizedRegistryIdCommitment,
      fixture.scopeResourceTypeCommitment,
      fixture.scopeResourceIdCommitment,
      prepared.policyCommitment,
      bytes32Commitment(fixture.trustLevel),
      prepared.evidenceHash,
      signers.slice(1),
    );
  }

  prepareRecognitionDecisionAction(
    fixture: RecognitionScenarioFixture,
    action: IssuerDecisionAction,
  ): PreparedRecognitionAction {
    if (action !== "approve" && action !== "activate") {
      throw new Error("Unsupported recognition decision action");
    }
    const current = this.simulator.getRecognition(fixture.recognitionIdCommitment);
    const ledger = this.simulator.getLedger();
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      recognitionId: Uint8Array.from(fixture.recognitionIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      actionKind: Uint8Array.from(action === "approve" ? AUTHORIZE_RECOGNITION_ACTION_KIND : ACTIVATE_RECOGNITION_ACTION_KIND),
      actionPayloadHash: computeUpdateRecognitionPayloadHash(
        fixture.recognitionIdCommitment, current.lifecycleEventHash, current.evidenceHash,
      ),
      actionSequence: ledger.governanceActionCount,
      previousLifecycleEventHash: Uint8Array.from(current.lifecycleEventHash),
      evidenceHash: Uint8Array.from(current.evidenceHash),
    };
  }

  executeRecognitionDecisionWithSignatures(
    fixture: RecognitionScenarioFixture,
    action: IssuerDecisionAction,
    signers: readonly MaintainerCoAuthorizer[],
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Recognition decision requires a maintainer signature");
    const prepared = this.prepareRecognitionDecisionAction(fixture, action);
    if (action === "approve") {
      return this.simulator.authorizeRecognition(
        primary.keyId, primary.publicKey, primary.signature,
        fixture.recognitionIdCommitment, prepared.evidenceHash, signers.slice(1),
      );
    }
    return this.simulator.activateRecognition(
      primary.keyId, primary.publicKey, primary.signature,
      fixture.recognitionIdCommitment, prepared.evidenceHash, signers.slice(1),
    );
  }

  private fixtureRecognitionDecision(fixture: RecognitionScenarioFixture, action: IssuerDecisionAction): Uint8Array {
    const prepared = this.prepareRecognitionDecisionAction(fixture, action);
    return this.executeRecognitionDecisionWithSignatures(fixture, action, [
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
      ),
    ]);
  }

  approveRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    return this.fixtureRecognitionDecision(fixture, "approve");
  }

  activateRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    return this.fixtureRecognitionDecision(fixture, "activate");
  }

  authorizeRecognition(fixture: RecognitionScenarioFixture): Uint8Array {
    this.proposeRecognition(fixture);
    this.approveRecognition(fixture);
    return this.activateRecognition(fixture);
  }

  proposeAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    return this.proposeAuditorWithApplicationEvidence(
      fixture,
      this.createApplicationEvidence({
        applicationId: fixture.authorizationId,
        subjectDid: fixture.subjectDid,
        role: "auditor",
        scope: createAuditorAuthorizationScopeFixture(fixture),
      }),
    );
  }

  proposeAuditorWithApplicationEvidence(
    fixture: AuditorScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createAuditorAuthorizationScopeFixture(fixture),
      challengeHash: sha256Hex(`challenge:${fixture.authorizationId}`),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId },
    },
  ): Uint8Array {
    const prepared = this.prepareAuditorProposalAction(fixture, evidence, expectedEvidence);
    return this.executeAuditorProposalWithSignatures(fixture, evidence, [
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind,
        prepared.actionPayloadHash,
        prepared.actionSequence,
      ),
    ], this.signAuditorProposalEvidence(prepared), expectedEvidence);
  }

  prepareAuditorProposalAction(
    fixture: AuditorScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createAuditorAuthorizationScopeFixture(fixture),
      challengeHash: sha256Hex(`challenge:${fixture.authorizationId}`),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId },
    },
  ): PreparedAuditorProposalAction {
    if (
      expectedEvidence.scope.role !== "auditor" ||
      expectedEvidence.governedResource.type !== "requestProfile" ||
      expectedEvidence.governedResource.id !== fixture.scopeResourceId ||
      computeAuthorizationScopeCommitment(expectedEvidence.scope) !==
        computeAuthorizationScopeCommitment(createAuditorAuthorizationScopeFixture(fixture))
    ) {
      throw new Error("Auditor proposal scope does not match governed request profile");
    }
    const proposedEvidenceHash = this.assertApplicationEvidence({
      evidence,
      applicationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      role: "auditor",
      ...expectedEvidence,
    });
    const ledger = this.simulator.getLedger();
    const baseAuditorPayloadHash = computeCreateAuditorAuthorizationPayloadHash(
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.requestResourceIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
      ledger.governancePolicyCommitment,
      bytes32Commitment(fixture.trustLevel),
      proposedEvidenceHash,
    );
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      authorizationId: Uint8Array.from(fixture.authorizationIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      policyVersion: ledger.governancePolicyVersion,
      actionKind: Uint8Array.from(PROPOSE_AUDITOR_ACTION_KIND),
      actionPayloadHash: computeAuditorEvidenceBoundProposalPayloadHash(
        baseAuditorPayloadHash,
        this.currentEvidenceVerifierAuthorizationId,
        this.currentEvidenceVerifierKeyIdCommitment,
        ledger.governancePolicyCommitment,
        ledger.governancePolicyVersion,
      ),
      actionSequence: ledger.governanceActionCount,
      evidenceHash: Uint8Array.from(proposedEvidenceHash),
      evidenceVerifierAuthorizationId: Uint8Array.from(this.currentEvidenceVerifierAuthorizationId),
      evidenceVerifierKeyIdCommitment: Uint8Array.from(this.currentEvidenceVerifierKeyIdCommitment),
    };
  }

  signAuditorProposalEvidence(prepared: PreparedAuditorProposalAction): TrustRegistryJubjubSignature {
    return signAuditorProposalEvidenceFromSeed(
      this.evidenceVerifierKey.seed,
      prepared.registryId,
      prepared.evidenceVerifierKeyIdCommitment,
      prepared.actionPayloadHash,
    );
  }

  executeAuditorProposalWithSignatures(
    fixture: AuditorScenarioFixture,
    evidence: ApplicationEvidenceSubmission,
    signers: readonly MaintainerCoAuthorizer[],
    verifierSignature: TrustRegistryJubjubSignature,
    expectedEvidence: SimulatorApplicationEvidenceExpectation = {
      scope: createAuditorAuthorizationScopeFixture(fixture),
      challengeHash: sha256Hex(`challenge:${fixture.authorizationId}`),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId },
    },
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Auditor proposal requires a maintainer signature");
    const prepared = this.prepareAuditorProposalAction(fixture, evidence, expectedEvidence);
    return this.simulator.proposeAuditorAuthorization(
      primary.keyId,
      primary.publicKey,
      primary.signature,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.requestResourceIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
      prepared.policyCommitment,
      bytes32Commitment(fixture.trustLevel),
      prepared.evidenceHash,
      prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment,
      verifierSignature,
      signers.slice(1),
    );
  }

  prepareAuditorDecisionAction(
    fixture: AuditorScenarioFixture,
    action: IssuerDecisionAction,
  ): PreparedIssuerDecisionAction {
    if (!["approve", "activate", "suspend", "revoke"].includes(action)) {
      throw new Error("Unsupported auditor decision action");
    }
    const current = this.simulator.getAuditorAuthorization(fixture.authorizationIdCommitment);
    const ledger = this.simulator.getLedger();
    const evidenceHash = action === "approve" || action === "activate"
      ? current.evidenceHash : bytes32Commitment(`${fixture.authorizationId}:${action}`);
    const actionKinds = {
      approve: AUTHORIZE_AUDITOR_ACTION_KIND,
      activate: ACTIVATE_AUDITOR_ACTION_KIND,
      suspend: SUSPEND_AUDITOR_ACTION_KIND,
      revoke: REVOKE_AUDITOR_ACTION_KIND,
    };
    return {
      registryId: Uint8Array.from(this.registryIdCommitment),
      authorizationId: Uint8Array.from(fixture.authorizationIdCommitment),
      policyCommitment: Uint8Array.from(ledger.governancePolicyCommitment),
      actionKind: Uint8Array.from(actionKinds[action]),
      actionPayloadHash: computeUpdateAuditorAuthorizationPayloadHash(
        fixture.authorizationIdCommitment, current.lifecycleEventHash, evidenceHash,
      ),
      actionSequence: ledger.governanceActionCount,
      previousLifecycleEventHash: Uint8Array.from(current.lifecycleEventHash),
      evidenceHash: Uint8Array.from(evidenceHash),
    };
  }

  executeAuditorDecisionWithSignatures(
    fixture: AuditorScenarioFixture,
    action: IssuerDecisionAction,
    signers: readonly MaintainerCoAuthorizer[],
  ): Uint8Array {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Auditor decision requires a maintainer signature");
    const prepared = this.prepareAuditorDecisionAction(fixture, action);
    if (action === "approve") {
      return this.simulator.authorizeAuditorAuthorization(
        primary.keyId, primary.publicKey, primary.signature,
        fixture.authorizationIdCommitment, prepared.evidenceHash, signers.slice(1),
      );
    }
    const circuit = action === "activate" ? this.simulator.activateAuditorAuthorization.bind(this.simulator)
      : action === "suspend" ? this.simulator.suspendAuditorAuthorization.bind(this.simulator)
        : this.simulator.revokeAuditorAuthorization.bind(this.simulator);
    return circuit(primary.keyId, primary.publicKey, primary.signature,
      fixture.authorizationIdCommitment, prepared.evidenceHash, signers.slice(1));
  }

  private fixtureAuditorDecision(fixture: AuditorScenarioFixture, action: IssuerDecisionAction): Uint8Array {
    const prepared = this.prepareAuditorDecisionAction(fixture, action);
    return this.executeAuditorDecisionWithSignatures(fixture, action, [
      {
        keyId: this.bootstrapMaintainer.keyId,
        publicKey: this.bootstrapPublicKey,
        signature: this.bootstrapActionSignature(
          prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
        ),
      },
      ...this.maintainerCoAuthorizers(
        this.activeDefaultQuorumCoMaintainers(),
        prepared.actionKind,
        prepared.actionPayloadHash,
        prepared.actionSequence,
      ),
    ]);
  }

  approveAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    return this.fixtureAuditorDecision(fixture, "approve");
  }

  activateAuditor(fixture: AuditorScenarioFixture): Uint8Array {
    return this.fixtureAuditorDecision(fixture, "activate");
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
    this.assertSupportedContractFormat();
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

  readIssuerAuthorizationStatus(
    fixture: IssuerScenarioFixture,
  ): AuthorizationRecord["status"] {
    this.assertSupportedContractFormat();
    return contractStatusName(
      this.simulator.getIssuerAuthorization(fixture.authorizationIdCommitment).status,
    );
  }

  buildIssuerHistoricalEvidence(
    fixture: IssuerScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    this.assertSupportedContractFormat();
    const record = this.simulator.getIssuerAuthorization(
      fixture.authorizationIdCommitment,
    );
    const authorization = this.buildIssuerAuthorizationRecord(fixture, record);
    return this.buildEvidenceBundle({
      authorization,
      subjectDid: fixture.subjectDid,
      statusPolicyBinding: this.issuerStatusPolicyBinding(fixture),
      lastStatusSequence: record.lastStatusSequence,
    });
  }

  evaluateCurrentVerifierDecision(
    fixture: VerifierScenarioFixture,
    options: { expectedRegistryId?: string } = {},
  ): TrustRegistryEvidenceBundle {
    this.assertSupportedContractFormat();
    this.assertRegistryId(options.expectedRegistryId);
    this.simulator.assertVerifierAuthorized(
      fixture.subjectDidCommitment,
      fixture.requestResourceIdCommitment,
      fixture.allowedAttributeSetCommitment,
      fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment,
    );
    const bundle = this.buildVerifierHistoricalEvidence(fixture);
    this.assertPublishedEpochEvidence(bundle);
    return bundle;
  }

  readVerifierAuthorizationStatus(
    fixture: VerifierScenarioFixture,
  ): AuthorizationRecord["status"] {
    this.assertSupportedContractFormat();
    return contractStatusName(
      this.simulator.getVerifierAuthorization(fixture.authorizationIdCommitment).status,
    );
  }

  buildVerifierHistoricalEvidence(
    fixture: VerifierScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    this.assertSupportedContractFormat();
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
    this.assertSupportedContractFormat();
    this.assertRegistryId(options.expectedRegistryId);
    this.simulator.assertAuditorAuthorized(
      fixture.subjectDidCommitment,
      fixture.requestResourceIdCommitment,
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
    this.assertSupportedContractFormat();
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
    const ledger = this.assertSupportedContractFormat();
    this.assertRegistryId(bundle.registryId);
    const versionMatch = /^v([1-9]\d*)$/.exec(bundle.policy.version);
    if (versionMatch === null) {
      throw new Error("Policy version is invalid");
    }
    const version = BigInt(versionMatch[1]!);
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
    const expectedSnapshotRoot = computeGovernancePolicySnapshotCommitment(
      deriveGovernancePolicySnapshot(bundle.policy),
    );
    if (bundle.epoch.policyRoot !== expectedSnapshotRoot) {
      throw new Error("Epoch policy root does not match the policy snapshot");
    }
    if (!ledger.governancePolicyCommitmentsByVersion.member(version)) {
      throw new Error("Policy version is not committed to the ledger");
    }
    if (
      bytes32Hex(ledger.governancePolicyCommitmentsByVersion.lookup(version))
      !== expectedSnapshotRoot
    ) {
      throw new Error("Policy snapshot does not match the committed ledger version");
    }
    if (bundle.epoch.registryId !== this.registryId) {
      throw new Error(
        `Epoch registry mismatch: expected ${this.registryId}, got ${bundle.epoch.registryId}`,
      );
    }

    const evaluationTime = Date.parse(options.evaluationTime ?? bundle.generatedAt);
    if (!Number.isFinite(evaluationTime)) {
      throw new Error("Evaluation time is invalid");
    }
    if (evaluationTime < Date.parse(bundle.policy.effectiveFrom)) {
      throw new Error("Policy snapshot is not yet effective");
    }
    if (
      version < ledger.governancePolicyVersion
      && evaluationTime >= Date.parse(timestampForSequence(
        ledger.governancePolicyEffectiveFromByVersion.lookup(version + 1n),
      ))
    ) {
      throw new Error("Policy snapshot is superseded at the evaluation time");
    }
    if (evaluationTime < Date.parse(bundle.epoch.validFrom)) {
      throw new Error("Epoch is not yet valid for this evidence bundle");
    }
    if (evaluationTime > Date.parse(bundle.epoch.validUntil)) {
      throw new Error("Epoch is stale for this evidence bundle");
    }

    // External callers can bypass the TypeScript tuple type at runtime.
    if (bundle.epoch.maintainerSignatures.length !== 1) {
      throw new Error("Epoch commitment must include exactly one maintainer signature");
    }
    const maintainerSignature = bundle.epoch.maintainerSignatures[0]!;
    if (maintainerSignature.algorithm !== "jubjub-schnorr") {
      throw new Error("Epoch maintainer signature algorithm is unsupported");
    }
    if (!sameBytes(bytes32Commitment(maintainerSignature.keyId), epochRecord.maintainerKeyId)) {
      throw new Error("Epoch maintainer DID method does not match its ledger key commitment");
    }
    let signature: ReturnType<typeof decodeCanonicalJubjubSignatureHex>;
    try {
      signature = decodeCanonicalJubjubSignatureHex(maintainerSignature.signature);
    } catch (error) {
      throw new Error("Epoch maintainer signature encoding is invalid", { cause: error });
    }
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
    if (
      !(epochRecord.publicationPolicyCommitment instanceof Uint8Array)
      || epochRecord.publicationPolicyCommitment.length !== 32
      || epochRecord.publicationPolicyCommitment.every((byte) => byte === 0)
    ) {
      throw new Error("Epoch publication policy commitment is missing or malformed");
    }
    let verified = false;
    let verificationFault: unknown;
    try {
      verified = verifyPolicyBoundMaintainerAction(
        maintainerRecord.publicKey,
        this.registryIdCommitment,
        epochRecord.publicationPolicyCommitment,
        CREATE_EPOCH_ACTION_KIND,
        payloadHash,
        epochRecord.publishedAtSequence,
        signature,
      );
    } catch (error) {
      verificationFault = error;
    }
    if (!verified) {
      throw new Error("Epoch maintainer signature is invalid", { cause: verificationFault });
    }
  }

  buildRecognitionHistoricalEvidence(
    fixture: RecognitionScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    this.assertSupportedContractFormat();
    const record = this.simulator.getRecognition(fixture.recognitionIdCommitment);
    const recognition = this.buildRecognitionRecord(fixture, record);
    return this.buildEvidenceBundle({
      subjectDid: fixture.recognizedAuthorityDid,
      lastStatusSequence: record.lastStatusSequence,
      recognition,
    });
  }

  readRecognitionStatus(
    fixture: RecognitionScenarioFixture,
  ): RecognitionRecord["status"] {
    this.assertSupportedContractFormat();
    return contractStatusName(
      this.simulator.getRecognition(fixture.recognitionIdCommitment).status,
    );
  }

  buildAuditorHistoricalEvidence(
    fixture: AuditorScenarioFixture,
  ): TrustRegistryEvidenceBundle {
    this.assertSupportedContractFormat();
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
    const signature = this.signMaintainerActionFromSeed(
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
    additionalMaintainers: readonly MaintainerScenarioFixture[] = [],
  ): Uint8Array {
    const evidenceHash = bytes32Commitment(
      `${fixture.authorizationId}:${actionName}`,
    );
    const currentRecord = this.simulator.getIssuerAuthorization(
      fixture.authorizationIdCommitment,
    );
    const actionSequence = this.simulator.getLedger().governanceActionCount;
    const actionPayloadHash = computeUpdateIssuerAuthorizationPayloadHash(
      fixture.authorizationIdCommitment,
      currentRecord.lifecycleEventHash,
      evidenceHash,
    );
    const signature = this.signMaintainerActionFromSeed(
      this.bootstrapMaintainer.seed,
      this.registryIdCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    );

    if (actionName === "suspend") {
      return this.simulator.suspendIssuerAuthorization(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.authorizationIdCommitment,
        evidenceHash,
        this.maintainerCoAuthorizers(
          additionalMaintainers,
          actionKind,
          actionPayloadHash,
          actionSequence,
        ),
      );
    }
    if (actionName === "revoke") {
      return this.simulator.revokeIssuerAuthorization(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        fixture.authorizationIdCommitment,
        evidenceHash,
        this.maintainerCoAuthorizers(
          additionalMaintainers,
          actionKind,
          actionPayloadHash,
          actionSequence,
        ),
      );
    }
    return this.simulator.archiveIssuerAuthorization(
      this.bootstrapMaintainer.keyId,
      this.bootstrapPublicKey,
      signature,
      fixture.authorizationIdCommitment,
      evidenceHash,
      this.maintainerCoAuthorizers(
        additionalMaintainers,
        actionKind,
        actionPayloadHash,
        actionSequence,
      ),
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
    const signature = this.signMaintainerActionFromSeed(
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
    const signature = this.signMaintainerActionFromSeed(
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
    const signature = this.signMaintainerActionFromSeed(
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

  private assertSupportedContractFormat(): ReturnType<TrustRegistrySimulator["getLedger"]> {
    const ledger = this.simulator.getLedger();
    if (ledger.contractVersion !== 1n) {
      throw new Error("Unsupported trust registry format");
    }
    return ledger;
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

  private issuerStatusPolicyBinding(
    fixture: IssuerScenarioFixture,
  ): IssuerStatusPolicyBinding {
    return {
      version: "tr-issuer-status-policy-v1",
      trustRegistryId: this.registryId,
      issuerAuthorizationId: fixture.authorizationId,
      statusRegistryId: fixture.statusRegistryId,
      statusAuthorityVerificationMethod: fixture.statusAuthorityVerificationMethod,
      statusPolicyId: fixture.statusPolicyId,
      statusPolicyVersion: fixture.statusPolicyVersion,
      statusPolicyContentCommitment: fixture.statusPolicyContentCommitment,
    };
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
      ...(input.role === "issuer"
        ? { statusPolicyBindingCommitment: bytes32Hex(
          (record as ContractIssuerAuthorizationRecord).statusPolicyBindingCommitment,
        ) }
        : {}),
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

  private policyRevisionAtSequence(sequence: bigint): (typeof this.policyRevisions)[number] {
    const revision = [...this.policyRevisions]
      .reverse()
      .find((candidate) => candidate.effectiveFromSequence <= sequence);
    if (revision === undefined) {
      throw new Error("No governance policy revision applies to this sequence");
    }
    return revision;
  }

  private prepareEpochPublicationAction(input: {
    statementLeafHash: string;
    lastStatusSequence: bigint;
    lifecycleEventRoot: string;
  }): PreparedRegistryEpochPublicationAction {
    this.assertSupportedContractFormat();
    const epochId = createScopedIdentifier("epoch", this.registryId,
      `seq-${input.lastStatusSequence.toString()}`);
    const epochIdCommitment = bytes32Commitment(epochId);
    const stateRoot = hashHexToBytes32(computeSingleStatementStateRoot(
      input.statementLeafHash, input.lifecycleEventRoot,
    ));
    const eventRoot = hashHexToBytes32(input.lifecycleEventRoot);
    const policyRoot = Uint8Array.from(this.policyRevisionAtSequence(input.lastStatusSequence).commitment);
    const validFromSequence = input.lastStatusSequence;
    const validUntilSequence = input.lastStatusSequence + 60n;
    return {
      epochId,
      registryId: Uint8Array.from(this.registryIdCommitment),
      epochIdCommitment,
      policyCommitment: Uint8Array.from(this.simulator.getLedger().governancePolicyCommitment),
      actionKind: Uint8Array.from(CREATE_EPOCH_ACTION_KIND),
      actionPayloadHash: computeCreateEpochCommitmentPayloadHash(
        epochIdCommitment, stateRoot, eventRoot, policyRoot,
        validFromSequence, validUntilSequence,
      ),
      actionSequence: this.simulator.getLedger().governanceActionCount,
      stateRoot,
      eventRoot,
      policyRoot,
      validFromSequence,
      validUntilSequence,
    };
  }

  prepareRegistryEpochPublicationAction(label = "registry-current"): PreparedRegistryEpochPublicationAction {
    const ledger = this.assertSupportedContractFormat();
    const statementId = createScopedIdentifier("registry-snapshot", this.registryId, label);
    return this.prepareEpochPublicationAction({
      statementLeafHash: computeRegistryStatementLeafHash({
        registryId: this.registryId,
        statementId,
        statementStatus: this.registryRecord.status,
        lifecycleEventRoot: this.registryRecord.lifecycleEventRoot,
      }),
      lastStatusSequence: ledger.governanceActionCount,
      lifecycleEventRoot: this.registryRecord.lifecycleEventRoot,
    });
  }

  /** Compact verifies the active maintainer keys, signatures, policy, sequence, and quorum. */
  executeRegistryEpochPublicationWithSignatures(
    label: string,
    signers: readonly MaintainerCoAuthorizer[],
  ): EpochCommitment {
    const primary = signers[0];
    if (primary === undefined) throw new Error("Epoch publication requires a maintainer signature");
    const prepared = this.prepareRegistryEpochPublicationAction(label);
    const signersWithDids = signers.map((signer) => {
      const maintainer = [...this.knownMaintainers.values()].find((candidate) =>
        sameBytes(candidate.keyId, signer.keyId));
      if (maintainer === undefined) throw new Error("Epoch signer is not a known maintainer");
      return { signer, maintainer };
    });
    const eventHash = this.simulator.publishEpochCommitment(
      primary.keyId, primary.publicKey, primary.signature,
      prepared.epochIdCommitment, prepared.stateRoot, prepared.eventRoot,
      prepared.policyRoot, prepared.validFromSequence, prepared.validUntilSequence,
      signers.slice(1),
    );
    this.epochPublicationWitnesses.set(prepared.epochId, {
      eventHash: bytes32Hex(eventHash),
      signatures: signersWithDids.map(({ signer, maintainer }) => ({
        keyId: `${maintainer.subjectDid}#key-1`,
        algorithm: "jubjub-schnorr" as const,
        signature: bytes32Hex(encodeJubjubSignature(signer.signature)),
      })),
    });
    return this.buildEpochCommitment(prepared.epochId,
      this.simulator.getEpochCommitment(prepared.epochIdCommitment));
  }

  private ensurePublishedEpochCommitment(input: {
    statementId: string;
    statementLeafHash: string;
    lastStatusSequence: bigint;
    lifecycleEventRoot: string;
    statementStatus: string;
  }): EpochCommitment {
    const prepared = this.prepareEpochPublicationAction(input);

    let record: ContractEpochCommitmentRecord;
    try {
      record = this.simulator.getEpochCommitment(prepared.epochIdCommitment);
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      if (!/not registered/i.test(message)) {
        throw error;
      }

      const signature = this.signMaintainerActionFromSeed(
        this.bootstrapMaintainer.seed,
        prepared.registryId,
        prepared.actionKind,
        prepared.actionPayloadHash,
        prepared.actionSequence,
      );
      const coMaintainers = this.activeDefaultQuorumCoMaintainers();
      const coAuthorizers = this.maintainerCoAuthorizers(
        coMaintainers,
        prepared.actionKind,
        prepared.actionPayloadHash,
        prepared.actionSequence,
      );
      const eventHash = this.simulator.publishEpochCommitment(
        this.bootstrapMaintainer.keyId,
        this.bootstrapPublicKey,
        signature,
        prepared.epochIdCommitment,
        prepared.stateRoot,
        prepared.eventRoot,
        prepared.policyRoot,
        prepared.validFromSequence,
        prepared.validUntilSequence,
        coAuthorizers,
      );
      record = this.simulator.getEpochCommitment(prepared.epochIdCommitment);
      this.epochPublicationWitnesses.set(prepared.epochId, {
        eventHash: bytes32Hex(eventHash),
        signatures: [
          {
            keyId: `${this.maintainerDid}#key-1`,
            algorithm: "jubjub-schnorr",
            signature: bytes32Hex(encodeJubjubSignature(signature)),
          },
          ...coMaintainers.map((maintainer, index) => ({
            keyId: `${maintainer.subjectDid}#key-1`,
            algorithm: "jubjub-schnorr" as const,
            signature: bytes32Hex(encodeJubjubSignature(coAuthorizers[index]!.signature)),
          })),
        ],
      });
    }

    return this.buildEpochCommitment(prepared.epochId, record);
  }

  publishRegistryEpoch(label = "registry-current"): EpochCommitment {
    const ledger = this.assertSupportedContractFormat();
    const statementId = createScopedIdentifier("registry-snapshot", this.registryId, label);
    return this.ensurePublishedEpochCommitment({
      statementId,
      statementLeafHash: computeRegistryStatementLeafHash({
        registryId: this.registryId,
        statementId,
        statementStatus: this.registryRecord.status,
        lifecycleEventRoot: this.registryRecord.lifecycleEventRoot,
      }),
      lastStatusSequence: ledger.governanceActionCount,
      lifecycleEventRoot: this.registryRecord.lifecycleEventRoot,
      statementStatus: this.registryRecord.status,
    });
  }

  getEpochPublicationWitness(epochId: string): {
    eventHash: string;
    signatures: Array<{ keyId: string; algorithm: "jubjub-schnorr"; signature: string }>;
  } {
    const witness = this.epochPublicationWitnesses.get(epochId);
    if (witness === undefined) {
      throw new Error("Epoch publication witness is not available in this simulator session");
    }
    const record = this.simulator.getEpochCommitment(bytes32Commitment(epochId));
    if (bytes32Hex(record.publicationEventHash) !== witness.eventHash) {
      throw new Error("Epoch publication witness does not match the ledger event");
    }
    return {
      eventHash: witness.eventHash,
      signatures: witness.signatures.map((signer) => ({ ...signer })),
    };
  }

  getPublishedEpochCommitment(epochId: string): EpochCommitment {
    return this.buildEpochCommitment(epochId,
      this.simulator.getEpochCommitment(bytes32Commitment(epochId)));
  }

  private buildEpochCommitment(
    epochId: string,
    record: ContractEpochCommitmentRecord,
  ): EpochCommitment {
    const primary = [...this.knownMaintainers.values()].find((maintainer) =>
      sameBytes(maintainer.keyId, record.maintainerKeyId));
    if (primary === undefined) throw new Error("Epoch primary signer is not a known maintainer");
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
          keyId: `${primary.subjectDid}#key-1`,
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
    statusPolicyBinding?: IssuerStatusPolicyBinding;
  }): TrustRegistryEvidenceBundle {
    const bundleRole = input.authorization?.role ?? "recognition";
    const bundleSubjectId =
      input.authorization?.authorizationId ?? input.recognition?.recognitionId;
    const statementStatus =
      input.authorization?.status ?? input.recognition?.status;
    const lifecycleEventRoot =
      input.authorization?.lifecycleEventRoot
      ?? input.recognition?.lifecycleEventRoot;
    const leafHash =
      input.authorization !== undefined
        ? computeAuthorizationStatementLeafHash(input.authorization)
        : computeRecognitionStatementLeafHash(input.recognition!);
    const epoch = this.ensurePublishedEpochCommitment({
      statementId: bundleSubjectId ?? "missing",
      statementLeafHash: leafHash,
      lastStatusSequence: input.lastStatusSequence,
      lifecycleEventRoot: lifecycleEventRoot ?? sha256Hex("missing"),
      statementStatus: statementStatus ?? "unknown",
    });
    const policyRevision = this.policyRevisionAtSequence(input.lastStatusSequence);
    if (epoch.policyRoot !== bytes32Hex(policyRevision.commitment)) {
      throw new Error("Published epoch does not match the historical policy revision");
    }

    return TrustRegistryEvidenceBundleSchema.parse({
      bundleId: createScopedIdentifier(
        "bundle",
        bundleRole,
        bundleSubjectId ?? "missing",
      ),
      generatedAt: epoch.validFrom,
      registryId: this.registryId,
      subjectDid: input.subjectDid,
      policy: policyRevision.record,
      epoch,
      inclusionProof: {
        proofType: "merkle-inclusion",
        root: epoch.stateRoot,
        leafHash,
        path: [epoch.eventRoot],
        leafIndex: 0,
      },
      ...(input.authorization !== undefined
        ? {
            authorization: input.authorization,
            ...(input.referencedStatusRegistryId !== undefined
              ? { referencedStatusRegistryId: input.referencedStatusRegistryId }
              : {}),
            statusPolicyBinding: input.statusPolicyBinding,
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
