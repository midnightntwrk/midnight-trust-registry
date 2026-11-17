import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  type IssuerResourceType,
} from "@midnight-ntwrk/trust-registry-contract";
import { TrustRegistrySimulator } from "@midnight-ntwrk/trust-registry-contract/testing";
import type {
  AuditorAuthorizationRecord,
  EpochCommitmentRecord,
  IssuerAuthorizationRecord,
  MaintainerMembershipRecord,
  MaintainerRecord,
  RecognitionRecord,
  VerifierAuthorizationRecord,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  TrustRegistryEvidenceBundleSchema,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  verifyAuditorAuthorizationBundle,
  verifyIssuerAuthorizationBundle,
  verifyRecognitionBundle,
  verifyVerifierAuthorizationBundle,
  type BundleVerificationOptions,
} from "./evidence.js";
import { verifyAuditorRequestMandate, type AuditorMandate, type AuditorMandateOptions } from "./auditor-mandate.js";
import type { AuthorizationScope } from "@midnight-ntwrk/trust-registry-domain";
import { bytes32Commitment, bytes32Hex, defaultSequenceToTimestamp, hashHexToBytes32, sameBytes32 } from "./utils.js";

type SimulatorBundleVerificationOptions = Omit<
  BundleVerificationOptions,
  "epochRecord" | "maintainerPublicKey" | "registryIdCommitment" | "networkIdCommitment" | "contractAddress" | "policySupersededAt"
>;

export class TrustRegistrySimulatorClient {
  readonly #simulator: TrustRegistrySimulator;

  constructor(simulator: TrustRegistrySimulator) {
    this.#simulator = simulator;
  }

  private async requireSupportedLedger(): ReturnType<TrustRegistrySimulator["getLedger"]> {
    const ledger = await this.#simulator.getLedger();
    if (ledger.contractVersion !== 1n) {
      throw new Error("Unsupported trust registry format");
    }
    return ledger;
  }

  async getIssuerAuthorizationById(
    authorizationId: string | Uint8Array,
  ): Promise<IssuerAuthorizationRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getIssuerAuthorization(this.asBytes32(authorizationId));
  }

  async getCurrentIssuerAuthorization(input: {
    subjectDid: string | Uint8Array;
    resourceType: IssuerResourceType;
    resourceId: string | Uint8Array;
  }): Promise<IssuerAuthorizationRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getCurrentIssuerAuthorization(
      this.asBytes32(input.subjectDid),
      input.resourceType,
      this.asBytes32(input.resourceId),
    );
  }

  async getVerifierAuthorizationById(
    authorizationId: string | Uint8Array,
  ): Promise<VerifierAuthorizationRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getVerifierAuthorization(this.asBytes32(authorizationId));
  }

  async getCurrentVerifierAuthorization(input: {
    subjectDid: string | Uint8Array;
    requestResourceId: string | Uint8Array;
    allowedAttributeSetCommitment: string | Uint8Array;
    allowedPredicateSetCommitment: string | Uint8Array;
    disclosureLevelCommitment: string | Uint8Array;
  }): Promise<VerifierAuthorizationRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getCurrentVerifierAuthorization(
      this.asBytes32(input.subjectDid),
      this.asBytes32(input.requestResourceId),
      this.asBytes32(input.allowedAttributeSetCommitment),
      this.asBytes32(input.allowedPredicateSetCommitment),
      this.asBytes32(input.disclosureLevelCommitment),
    );
  }

  async getAuditorAuthorizationById(
    authorizationId: string | Uint8Array,
  ): Promise<AuditorAuthorizationRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getAuditorAuthorization(this.asBytes32(authorizationId));
  }

  async getCurrentAuditorAuthorization(input: {
    subjectDid: string | Uint8Array;
    requestResourceId: string | Uint8Array;
    allowedAttributeSetCommitment: string | Uint8Array;
    allowedPredicateSetCommitment: string | Uint8Array;
    disclosureLevelCommitment: string | Uint8Array;
  }): Promise<AuditorAuthorizationRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getCurrentAuditorAuthorization(
      this.asBytes32(input.subjectDid),
      this.asBytes32(input.requestResourceId),
      this.asBytes32(input.allowedAttributeSetCommitment),
      this.asBytes32(input.allowedPredicateSetCommitment),
      this.asBytes32(input.disclosureLevelCommitment),
    );
  }

  async getRecognitionById(recognitionId: string | Uint8Array): Promise<RecognitionRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getRecognition(this.asBytes32(recognitionId));
  }

  async getCurrentRecognition(input: {
    recognizedAuthorityDid: string | Uint8Array;
    recognizedRegistryId: string | Uint8Array;
    scopeResourceType: string | Uint8Array;
    scopeResourceId: string | Uint8Array;
  }): Promise<RecognitionRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getCurrentRecognition(
      this.asBytes32(input.recognizedAuthorityDid),
      this.asBytes32(input.recognizedRegistryId),
      this.asBytes32(input.scopeResourceType),
      this.asBytes32(input.scopeResourceId),
    );
  }

  async getEpochCommitmentById(epochId: string | Uint8Array): Promise<EpochCommitmentRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getEpochCommitment(this.asBytes32(epochId));
  }

  async getCurrentEpochCommitment(): Promise<EpochCommitmentRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getCurrentEpochCommitment();
  }

  async getMaintainerMembershipById(
    maintainerId: string | Uint8Array,
  ): Promise<MaintainerMembershipRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getMaintainerMembership(this.asBytes32(maintainerId));
  }

  async getCurrentMaintainerMembership(
    subjectDid: string | Uint8Array,
  ): Promise<MaintainerMembershipRecord> {
    await this.requireSupportedLedger();
    return this.#simulator.getCurrentMaintainerMembership(this.asBytes32(subjectDid));
  }

  async verifyIssuerAuthorizationBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: SimulatorBundleVerificationOptions,
  ): Promise<TrustRegistryEvidenceBundle> {
    return verifyIssuerAuthorizationBundle(bundle, {
      ...options,
      ...await this.buildEpochContext(bundle, options.sequenceToTimestamp),
    });
  }

  async verifyVerifierAuthorizationBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: SimulatorBundleVerificationOptions,
  ): Promise<TrustRegistryEvidenceBundle> {
    return verifyVerifierAuthorizationBundle(bundle, {
      ...options,
      ...await this.buildEpochContext(bundle, options.sequenceToTimestamp),
    });
  }

  async verifyAuditorAuthorizationBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: SimulatorBundleVerificationOptions,
  ): Promise<TrustRegistryEvidenceBundle> {
    return verifyAuditorAuthorizationBundle(bundle, {
      ...options,
      ...await this.buildEpochContext(bundle, options.sequenceToTimestamp),
    });
  }

  async verifyAuditorRequestMandate(
    bundle: TrustRegistryEvidenceBundle,
    requestedScope: Extract<AuthorizationScope, { role: "auditor" }>,
    options: Omit<AuditorMandateOptions, "epochRecord" | "maintainerPublicKey" | "registryIdCommitment" | "networkIdCommitment" | "contractAddress" | "policySupersededAt" | "currentAuthorizationRecord">,
  ): Promise<AuditorMandate> {
    if (bundle.authorization === undefined) throw new Error("Auditor mandate is unavailable");
    return verifyAuditorRequestMandate(bundle, requestedScope, {
      ...options,
      ...await this.buildEpochContext(bundle, options.sequenceToTimestamp),
      currentAuthorizationRecord: await this.getAuditorAuthorizationById(bundle.authorization.authorizationId),
    });
  }

  async verifyRecognitionBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: SimulatorBundleVerificationOptions,
  ): Promise<TrustRegistryEvidenceBundle> {
    return verifyRecognitionBundle(bundle, {
      ...options,
      ...await this.buildEpochContext(bundle, options.sequenceToTimestamp),
    });
  }

  async getMaintainerRecordByKeyId(
    keyId: Uint8Array,
  ): Promise<MaintainerRecord> {
    return (await this.requireSupportedLedger()).maintainerRecords.lookup(keyId);
  }

  private async buildEpochContext(
    bundle: TrustRegistryEvidenceBundle,
    sequenceToTimestamp: BundleVerificationOptions["sequenceToTimestamp"],
  ): Promise<Pick<
    BundleVerificationOptions,
    "epochRecord" | "maintainerPublicKey" | "registryIdCommitment" | "networkIdCommitment" | "contractAddress" | "policySupersededAt"
  >> {
    const ledger = await this.requireSupportedLedger();
    if (typeof bundle?.registryId !== "string" || bundle.registryId.length === 0) {
      throw new Error("Bundle registry ID is missing or malformed");
    }
    bundle = TrustRegistryEvidenceBundleSchema.parse(bundle);
    if (!sameBytes32(bytes32Commitment(bundle.registryId), ledger.registryId)) {
      throw new Error("Bundle registry ID does not match the simulator ledger");
    }
    const epochRecord = await this.getEpochCommitmentById(bundle.epoch.epochId);
    const versionMatch = /^v([1-9]\d*)$/.exec(bundle.policy.version);
    if (versionMatch === null) {
      throw new Error("Bundle policy version is invalid");
    }
    const version = BigInt(versionMatch[1]!);
    if (!ledger.governancePolicyCommitmentsByVersion.member(version)) {
      throw new Error("Bundle policy version is not committed to the ledger");
    }
    const policyCommitment = ledger.governancePolicyCommitmentsByVersion.lookup(version);
    if (bytes32Hex(policyCommitment) !== bundle.epoch.policyRoot) {
      throw new Error("Bundle policy root does not match the committed ledger version");
    }
    const nextVersion = version + 1n;
    const policySupersededAt = nextVersion <= ledger.governancePolicyVersion
      ? (sequenceToTimestamp ?? defaultSequenceToTimestamp)(
        ledger.governancePolicyEffectiveFromByVersion.lookup(nextVersion),
      )
      : undefined;
    const maintainerRecord = await this.getMaintainerRecordByKeyId(
      epochRecord.maintainerKeyId,
    );

    return {
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: ledger.registryId,
      networkIdCommitment: ledger.deploymentNetworkIdCommitment,
      contractAddress: hashHexToBytes32(this.#simulator.contractAddress),
      ...(policySupersededAt === undefined ? {} : { policySupersededAt }),
    };
  }

  private asBytes32(value: string | Uint8Array): Uint8Array {
    return typeof value === "string" ? bytes32Commitment(value) : value;
  }
}
