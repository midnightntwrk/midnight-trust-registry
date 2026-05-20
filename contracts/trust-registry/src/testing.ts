import { Buffer } from "node:buffer";

import {
  type CircuitContext,
  type CircuitResults,
  createCircuitContext,
  createConstructorContext,
  sampleContractAddress,
  type JubjubPoint,
} from "@midnight-ntwrk/compact-runtime";

import {
  type IssuerAuthorizationRecord,
  type RecognitionRecord,
  type VerifierAuthorizationRecord,
  type IssuerResourceType,
  Contract,
  type Ledger,
  ledger,
} from "./managed/trust-registry/contract/index.js";
import {
  type TrustRegistryPrivateState,
  trustRegistryWitnesses,
} from "./witnesses.js";

export const labelToBytes32 = (label: string): Uint8Array => {
  const bytes = new Uint8Array(32);
  bytes.set(Buffer.from(label).subarray(0, 32));
  return bytes;
};

export type MaintainerFixture = {
  seed: Uint8Array;
  keyId: Uint8Array;
};

export const createMaintainerFixture = (
  label: string,
  seedByte: number,
): MaintainerFixture => ({
  seed: new Uint8Array(32).fill(seedByte),
  keyId: labelToBytes32(`maintainer:${label}`),
});

export class TrustRegistrySimulator {
  readonly contract: Contract<TrustRegistryPrivateState>;
  circuitContext: CircuitContext<TrustRegistryPrivateState>;

  constructor() {
    this.contract = new Contract<TrustRegistryPrivateState>(
      trustRegistryWitnesses,
    );
    const initialState = this.contract.initialState(
      createConstructorContext({}, "0".repeat(64)),
    );
    this.circuitContext = createCircuitContext(
      sampleContractAddress(),
      initialState.currentZswapLocalState,
      initialState.currentContractState,
      initialState.currentPrivateState,
    );
  }

  getLedger(): Ledger {
    return ledger(this.circuitContext.currentQueryContext.state);
  }

  private executeCircuit<T>(
    circuitFn: () => CircuitResults<TrustRegistryPrivateState, T>,
  ): T {
    const result = circuitFn();
    this.circuitContext = createCircuitContext(
      sampleContractAddress(),
      result.context.currentZswapLocalState,
      result.context.currentQueryContext.state,
      result.context.currentPrivateState,
    );
    return result.result;
  }

  initializeRegistry(
    registryId: Uint8Array,
    registryDidCommitment: Uint8Array,
    governancePolicyCommitment: Uint8Array,
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    maintainerThreshold: bigint,
  ): void {
    this.executeCircuit(() =>
      this.contract.impureCircuits.initializeRegistry(
        this.circuitContext,
        registryId,
        registryDidCommitment,
        governancePolicyCommitment,
        maintainerKeyId,
        maintainerPublicKey,
        maintainerThreshold,
      ),
    );
  }

  authorizeMaintainerAction(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    actionKind: Uint8Array,
    actionPayloadHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeMaintainerAction(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        actionKind,
        actionPayloadHash,
      ),
    );
  }

  createIssuerAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    subjectDidCommitment: Uint8Array,
    resourceType: IssuerResourceType,
    resourceId: Uint8Array,
    policyId: Uint8Array,
    trustLevel: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.createIssuerAuthorization(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        authorizationId,
        subjectDidCommitment,
        resourceType,
        resourceId,
        policyId,
        trustLevel,
        evidenceHash,
      ),
    );
  }

  suspendIssuerAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendIssuerAuthorization(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        authorizationId,
        evidenceHash,
      ),
    );
  }

  revokeIssuerAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeIssuerAuthorization(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        authorizationId,
        evidenceHash,
      ),
    );
  }

  archiveIssuerAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.archiveIssuerAuthorization(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        authorizationId,
        evidenceHash,
      ),
    );
  }

  getIssuerAuthorization(
    authorizationId: Uint8Array,
  ): IssuerAuthorizationRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getIssuerAuthorization(
        this.circuitContext,
        authorizationId,
      ),
    );
  }

  getCurrentIssuerAuthorization(
    subjectDidCommitment: Uint8Array,
    resourceType: IssuerResourceType,
    resourceId: Uint8Array,
  ): IssuerAuthorizationRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentIssuerAuthorization(
        this.circuitContext,
        subjectDidCommitment,
        resourceType,
        resourceId,
      ),
    );
  }

  assertIssuerAuthorized(
    subjectDidCommitment: Uint8Array,
    resourceType: IssuerResourceType,
    resourceId: Uint8Array,
  ): void {
    this.executeCircuit(() =>
      this.contract.impureCircuits.assertIssuerAuthorized(
        this.circuitContext,
        subjectDidCommitment,
        resourceType,
        resourceId,
      ),
    );
  }

  createVerifierAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    subjectDidCommitment: Uint8Array,
    requestProfileId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
    policyId: Uint8Array,
    trustLevel: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.createVerifierAuthorization(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        authorizationId,
        subjectDidCommitment,
        requestProfileId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
        policyId,
        trustLevel,
        evidenceHash,
      ),
    );
  }

  suspendVerifierAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendVerifierAuthorization(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        authorizationId,
        evidenceHash,
      ),
    );
  }

  revokeVerifierAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeVerifierAuthorization(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        authorizationId,
        evidenceHash,
      ),
    );
  }

  archiveVerifierAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.archiveVerifierAuthorization(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        authorizationId,
        evidenceHash,
      ),
    );
  }

  getVerifierAuthorization(
    authorizationId: Uint8Array,
  ): VerifierAuthorizationRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getVerifierAuthorization(
        this.circuitContext,
        authorizationId,
      ),
    );
  }

  getCurrentVerifierAuthorization(
    subjectDidCommitment: Uint8Array,
    requestProfileId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): VerifierAuthorizationRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentVerifierAuthorization(
        this.circuitContext,
        subjectDidCommitment,
        requestProfileId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
      ),
    );
  }

  createRecognition(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    recognitionId: Uint8Array,
    recognizedAuthorityDidCommitment: Uint8Array,
    recognizedRegistryId: Uint8Array,
    scopeResourceType: Uint8Array,
    scopeResourceId: Uint8Array,
    policyId: Uint8Array,
    trustLevel: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.createRecognition(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        recognitionId,
        recognizedAuthorityDidCommitment,
        recognizedRegistryId,
        scopeResourceType,
        scopeResourceId,
        policyId,
        trustLevel,
        evidenceHash,
      ),
    );
  }

  suspendRecognition(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    recognitionId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendRecognition(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        recognitionId,
        evidenceHash,
      ),
    );
  }

  revokeRecognition(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    recognitionId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeRecognition(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        recognitionId,
        evidenceHash,
      ),
    );
  }

  archiveRecognition(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    recognitionId: Uint8Array,
    evidenceHash: Uint8Array,
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.archiveRecognition(
        this.circuitContext,
        maintainerKeyId,
        maintainerPublicKey,
        signature,
        recognitionId,
        evidenceHash,
      ),
    );
  }

  getRecognition(
    recognitionId: Uint8Array,
  ): RecognitionRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getRecognition(
        this.circuitContext,
        recognitionId,
      ),
    );
  }

  getCurrentRecognition(
    recognizedAuthorityDidCommitment: Uint8Array,
    recognizedRegistryId: Uint8Array,
    scopeResourceType: Uint8Array,
    scopeResourceId: Uint8Array,
  ): RecognitionRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentRecognition(
        this.circuitContext,
        recognizedAuthorityDidCommitment,
        recognizedRegistryId,
        scopeResourceType,
        scopeResourceId,
      ),
    );
  }

  assertRecognitionActive(
    recognizedAuthorityDidCommitment: Uint8Array,
    recognizedRegistryId: Uint8Array,
    scopeResourceType: Uint8Array,
    scopeResourceId: Uint8Array,
  ): void {
    this.executeCircuit(() =>
      this.contract.impureCircuits.assertRecognitionActive(
        this.circuitContext,
        recognizedAuthorityDidCommitment,
        recognizedRegistryId,
        scopeResourceType,
        scopeResourceId,
      ),
    );
  }

  assertVerifierAuthorized(
    subjectDidCommitment: Uint8Array,
    requestProfileId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): void {
    this.executeCircuit(() =>
      this.contract.impureCircuits.assertVerifierAuthorized(
        this.circuitContext,
        subjectDidCommitment,
        requestProfileId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
      ),
    );
  }
}
