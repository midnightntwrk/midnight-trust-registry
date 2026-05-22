import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  TrustRegistrySimulator,
  type IssuerResourceType,
} from "@midnight-ntwrk/trust-registry-contract";
import type {
  AuditorAuthorizationRecord,
  EpochCommitmentRecord,
  IssuerAuthorizationRecord,
  MaintainerMembershipRecord,
  MaintainerRecord,
  RecognitionRecord,
  VerifierAuthorizationRecord,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import type { TrustRegistryEvidenceBundle } from "@midnight-ntwrk/trust-registry-domain";

import {
  verifyAuditorAuthorizationBundle,
  verifyIssuerAuthorizationBundle,
  verifyRecognitionBundle,
  verifyVerifierAuthorizationBundle,
  type BundleVerificationOptions,
} from "./evidence.js";
import { bytes32Commitment } from "./utils.js";

type SimulatorBundleVerificationOptions = Omit<
  BundleVerificationOptions,
  "epochRecord" | "maintainerPublicKey" | "registryIdCommitment"
>;

export class TrustRegistrySimulatorClient {
  constructor(readonly simulator: TrustRegistrySimulator) {}

  getIssuerAuthorizationById(
    authorizationId: string | Uint8Array,
  ): IssuerAuthorizationRecord {
    return this.simulator.getIssuerAuthorization(this.asBytes32(authorizationId));
  }

  getCurrentIssuerAuthorization(input: {
    subjectDid: string | Uint8Array;
    resourceType: IssuerResourceType;
    resourceId: string | Uint8Array;
  }): IssuerAuthorizationRecord {
    return this.simulator.getCurrentIssuerAuthorization(
      this.asBytes32(input.subjectDid),
      input.resourceType,
      this.asBytes32(input.resourceId),
    );
  }

  getVerifierAuthorizationById(
    authorizationId: string | Uint8Array,
  ): VerifierAuthorizationRecord {
    return this.simulator.getVerifierAuthorization(this.asBytes32(authorizationId));
  }

  getCurrentVerifierAuthorization(input: {
    subjectDid: string | Uint8Array;
    requestProfileId: string | Uint8Array;
    allowedAttributeSetCommitment: string | Uint8Array;
    allowedPredicateSetCommitment: string | Uint8Array;
    disclosureLevelCommitment: string | Uint8Array;
  }): VerifierAuthorizationRecord {
    return this.simulator.getCurrentVerifierAuthorization(
      this.asBytes32(input.subjectDid),
      this.asBytes32(input.requestProfileId),
      this.asBytes32(input.allowedAttributeSetCommitment),
      this.asBytes32(input.allowedPredicateSetCommitment),
      this.asBytes32(input.disclosureLevelCommitment),
    );
  }

  getAuditorAuthorizationById(
    authorizationId: string | Uint8Array,
  ): AuditorAuthorizationRecord {
    return this.simulator.getAuditorAuthorization(this.asBytes32(authorizationId));
  }

  getCurrentAuditorAuthorization(input: {
    subjectDid: string | Uint8Array;
    requestProfileId: string | Uint8Array;
    allowedAttributeSetCommitment: string | Uint8Array;
    allowedPredicateSetCommitment: string | Uint8Array;
    disclosureLevelCommitment: string | Uint8Array;
  }): AuditorAuthorizationRecord {
    return this.simulator.getCurrentAuditorAuthorization(
      this.asBytes32(input.subjectDid),
      this.asBytes32(input.requestProfileId),
      this.asBytes32(input.allowedAttributeSetCommitment),
      this.asBytes32(input.allowedPredicateSetCommitment),
      this.asBytes32(input.disclosureLevelCommitment),
    );
  }

  getRecognitionById(recognitionId: string | Uint8Array): RecognitionRecord {
    return this.simulator.getRecognition(this.asBytes32(recognitionId));
  }

  getCurrentRecognition(input: {
    recognizedAuthorityDid: string | Uint8Array;
    recognizedRegistryId: string | Uint8Array;
    scopeResourceType: string | Uint8Array;
    scopeResourceId: string | Uint8Array;
  }): RecognitionRecord {
    return this.simulator.getCurrentRecognition(
      this.asBytes32(input.recognizedAuthorityDid),
      this.asBytes32(input.recognizedRegistryId),
      this.asBytes32(input.scopeResourceType),
      this.asBytes32(input.scopeResourceId),
    );
  }

  getEpochCommitmentById(epochId: string | Uint8Array): EpochCommitmentRecord {
    return this.simulator.getEpochCommitment(this.asBytes32(epochId));
  }

  getCurrentEpochCommitment(): EpochCommitmentRecord {
    return this.simulator.getCurrentEpochCommitment();
  }

  getMaintainerMembershipById(
    maintainerId: string | Uint8Array,
  ): MaintainerMembershipRecord {
    return this.simulator.getMaintainerMembership(this.asBytes32(maintainerId));
  }

  getCurrentMaintainerMembership(
    subjectDid: string | Uint8Array,
  ): MaintainerMembershipRecord {
    return this.simulator.getCurrentMaintainerMembership(this.asBytes32(subjectDid));
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
    return this.simulator.getLedger().maintainerRecords.lookup(keyId);
  }

  private buildEpochContext(bundle: TrustRegistryEvidenceBundle): Pick<
    BundleVerificationOptions,
    "epochRecord" | "maintainerPublicKey" | "registryIdCommitment"
  > {
    const epochRecord = this.getEpochCommitmentById(bundle.epoch.epochId);
    const maintainerRecord = this.getMaintainerRecordByKeyId(
      epochRecord.maintainerKeyId,
    );

    return {
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: this.asBytes32(bundle.registryId),
    };
  }

  private asBytes32(value: string | Uint8Array): Uint8Array {
    return typeof value === "string" ? bytes32Commitment(value) : value;
  }
}
