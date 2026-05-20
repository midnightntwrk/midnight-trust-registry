import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  TrustRegistrySimulator,
  type IssuerResourceType,
} from "@midnight-ntwrk/trust-registry-contract";
import type {
  EpochCommitmentRecord,
  IssuerAuthorizationRecord,
  MaintainerRecord,
  RecognitionRecord,
  VerifierAuthorizationRecord,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import type { TrustRegistryEvidenceBundle } from "@midnight-ntwrk/trust-registry-domain";

import {
  verifyIssuerAuthorizationBundle,
  verifyRecognitionBundle,
  verifyVerifierAuthorizationBundle,
  type BundleVerificationOptions,
} from "./evidence.js";
import { bytes32Commitment } from "./utils.js";

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

  verifyIssuerAuthorizationBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: Omit<BundleVerificationOptions, "epochRecord" | "maintainerPublicKey">,
  ): TrustRegistryEvidenceBundle {
    return verifyIssuerAuthorizationBundle(bundle, {
      ...options,
      ...this.buildEpochContext(bundle),
    });
  }

  verifyVerifierAuthorizationBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: Omit<BundleVerificationOptions, "epochRecord" | "maintainerPublicKey">,
  ): TrustRegistryEvidenceBundle {
    return verifyVerifierAuthorizationBundle(bundle, {
      ...options,
      ...this.buildEpochContext(bundle),
    });
  }

  verifyRecognitionBundle(
    bundle: TrustRegistryEvidenceBundle,
    options: Omit<BundleVerificationOptions, "epochRecord" | "maintainerPublicKey">,
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
    "epochRecord" | "maintainerPublicKey"
  > {
    const epochRecord = this.getEpochCommitmentById(bundle.epoch.epochId);
    const maintainerRecord = this.getMaintainerRecordByKeyId(
      epochRecord.maintainerKeyId,
    );

    return {
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
    };
  }

  private asBytes32(value: string | Uint8Array): Uint8Array {
    return typeof value === "string" ? bytes32Commitment(value) : value;
  }
}
