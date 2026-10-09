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
import { bytes32Commitment, bytes32Hex, defaultSequenceToTimestamp, sameBytes32 } from "./utils.js";

type SimulatorBundleVerificationOptions = Omit<
  BundleVerificationOptions,
  "epochRecord" | "maintainerPublicKey" | "registryIdCommitment" | "policySupersededAt"
>;

export class TrustRegistrySimulatorClient {
  readonly #simulator: TrustRegistrySimulator;

  constructor(simulator: TrustRegistrySimulator) {
    this.#simulator = simulator;
    this.requireSupportedLedger();
  }

  private requireSupportedLedger(): ReturnType<TrustRegistrySimulator["getLedger"]> {
    const ledger = this.#simulator.getLedger();
    if (ledger.contractVersion !== 1n) {
      throw new Error("Unsupported trust registry format");
    }
    return ledger;
  }

  getIssuerAuthorizationById(
    authorizationId: string | Uint8Array,
  ): IssuerAuthorizationRecord {
    this.requireSupportedLedger();
    return this.#simulator.getIssuerAuthorization(this.asBytes32(authorizationId));
  }

  getCurrentIssuerAuthorization(input: {
    subjectDid: string | Uint8Array;
    resourceType: IssuerResourceType;
    resourceId: string | Uint8Array;
  }): IssuerAuthorizationRecord {
    this.requireSupportedLedger();
    return this.#simulator.getCurrentIssuerAuthorization(
      this.asBytes32(input.subjectDid),
      input.resourceType,
      this.asBytes32(input.resourceId),
    );
  }

  getVerifierAuthorizationById(
    authorizationId: string | Uint8Array,
  ): VerifierAuthorizationRecord {
    this.requireSupportedLedger();
    return this.#simulator.getVerifierAuthorization(this.asBytes32(authorizationId));
  }

  getCurrentVerifierAuthorization(input: {
    subjectDid: string | Uint8Array;
    requestResourceId: string | Uint8Array;
    allowedAttributeSetCommitment: string | Uint8Array;
    allowedPredicateSetCommitment: string | Uint8Array;
    disclosureLevelCommitment: string | Uint8Array;
  }): VerifierAuthorizationRecord {
    this.requireSupportedLedger();
    return this.#simulator.getCurrentVerifierAuthorization(
      this.asBytes32(input.subjectDid),
      this.asBytes32(input.requestResourceId),
      this.asBytes32(input.allowedAttributeSetCommitment),
      this.asBytes32(input.allowedPredicateSetCommitment),
      this.asBytes32(input.disclosureLevelCommitment),
    );
  }

  getAuditorAuthorizationById(
    authorizationId: string | Uint8Array,
  ): AuditorAuthorizationRecord {
    this.requireSupportedLedger();
    return this.#simulator.getAuditorAuthorization(this.asBytes32(authorizationId));
  }

  getCurrentAuditorAuthorization(input: {
    subjectDid: string | Uint8Array;
    requestResourceId: string | Uint8Array;
    allowedAttributeSetCommitment: string | Uint8Array;
    allowedPredicateSetCommitment: string | Uint8Array;
    disclosureLevelCommitment: string | Uint8Array;
  }): AuditorAuthorizationRecord {
    this.requireSupportedLedger();
    return this.#simulator.getCurrentAuditorAuthorization(
      this.asBytes32(input.subjectDid),
      this.asBytes32(input.requestResourceId),
      this.asBytes32(input.allowedAttributeSetCommitment),
      this.asBytes32(input.allowedPredicateSetCommitment),
      this.asBytes32(input.disclosureLevelCommitment),
    );
  }

  getRecognitionById(recognitionId: string | Uint8Array): RecognitionRecord {
    this.requireSupportedLedger();
    return this.#simulator.getRecognition(this.asBytes32(recognitionId));
  }

  getCurrentRecognition(input: {
    recognizedAuthorityDid: string | Uint8Array;
    recognizedRegistryId: string | Uint8Array;
    scopeResourceType: string | Uint8Array;
    scopeResourceId: string | Uint8Array;
  }): RecognitionRecord {
    this.requireSupportedLedger();
    return this.#simulator.getCurrentRecognition(
      this.asBytes32(input.recognizedAuthorityDid),
      this.asBytes32(input.recognizedRegistryId),
      this.asBytes32(input.scopeResourceType),
      this.asBytes32(input.scopeResourceId),
    );
  }

  getEpochCommitmentById(epochId: string | Uint8Array): EpochCommitmentRecord {
    this.requireSupportedLedger();
    return this.#simulator.getEpochCommitment(this.asBytes32(epochId));
  }

  getCurrentEpochCommitment(): EpochCommitmentRecord {
    this.requireSupportedLedger();
    return this.#simulator.getCurrentEpochCommitment();
  }

  getMaintainerMembershipById(
    maintainerId: string | Uint8Array,
  ): MaintainerMembershipRecord {
    this.requireSupportedLedger();
    return this.#simulator.getMaintainerMembership(this.asBytes32(maintainerId));
  }

  getCurrentMaintainerMembership(
    subjectDid: string | Uint8Array,
  ): MaintainerMembershipRecord {
    this.requireSupportedLedger();
    return this.#simulator.getCurrentMaintainerMembership(this.asBytes32(subjectDid));
  }

  verifyIssuerAuthorizationBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: SimulatorBundleVerificationOptions,
  ): TrustRegistryEvidenceBundle {
    return verifyIssuerAuthorizationBundle(bundle, {
      ...options,
      ...this.buildEpochContext(bundle),
    });
  }

  verifyVerifierAuthorizationBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: SimulatorBundleVerificationOptions,
  ): TrustRegistryEvidenceBundle {
    return verifyVerifierAuthorizationBundle(bundle, {
      ...options,
      ...this.buildEpochContext(bundle),
    });
  }

  verifyAuditorAuthorizationBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: SimulatorBundleVerificationOptions,
  ): TrustRegistryEvidenceBundle {
    return verifyAuditorAuthorizationBundle(bundle, {
      ...options,
      ...this.buildEpochContext(bundle),
    });
  }

  verifyRecognitionBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: SimulatorBundleVerificationOptions,
  ): TrustRegistryEvidenceBundle {
    return verifyRecognitionBundle(bundle, {
      ...options,
      ...this.buildEpochContext(bundle),
    });
  }

  getMaintainerRecordByKeyId(
    keyId: Uint8Array,
  ): MaintainerRecord {
    return this.requireSupportedLedger().maintainerRecords.lookup(keyId);
  }

  private buildEpochContext(bundle: TrustRegistryEvidenceBundle): Pick<
    BundleVerificationOptions,
    "epochRecord" | "maintainerPublicKey" | "registryIdCommitment" | "policySupersededAt"
  > {
    const ledger = this.requireSupportedLedger();
    if (typeof bundle?.registryId !== "string" || bundle.registryId.length === 0) {
      throw new Error("Bundle registry ID is missing or malformed");
    }
    bundle = TrustRegistryEvidenceBundleSchema.parse(bundle);
    if (!sameBytes32(bytes32Commitment(bundle.registryId), ledger.registryId)) {
      throw new Error("Bundle registry ID does not match the simulator ledger");
    }
    const epochRecord = this.getEpochCommitmentById(bundle.epoch.epochId);
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
      ? defaultSequenceToTimestamp(
        ledger.governancePolicyEffectiveFromByVersion.lookup(nextVersion),
      )
      : undefined;
    const maintainerRecord = this.getMaintainerRecordByKeyId(
      epochRecord.maintainerKeyId,
    );

    return {
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: ledger.registryId,
      ...(policySupersededAt === undefined ? {} : { policySupersededAt }),
    };
  }

  private asBytes32(value: string | Uint8Array): Uint8Array {
    return typeof value === "string" ? bytes32Commitment(value) : value;
  }
}
