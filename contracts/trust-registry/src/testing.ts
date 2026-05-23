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
  type AuditorAuthorizationRecord,
  type EpochCommitmentRecord,
  type IssuerAuthorizationRecord,
  type MaintainerAuthorizationBundle,
  type MaintainerAuthorizationSigner,
  type MaintainerMembershipRecord,
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
  maintainerId: Uint8Array;
  didCommitment: Uint8Array;
  keyId: Uint8Array;
};

export type MaintainerCoAuthorizer = {
  keyId: Uint8Array;
  publicKey: JubjubPoint;
  signature: { announcement: JubjubPoint; response: bigint };
};

export const createMaintainerFixture = (
  label: string,
  seedByte: number,
): MaintainerFixture => ({
  seed: new Uint8Array(32).fill(seedByte),
  maintainerId: labelToBytes32(`maintainer-id:${label}`),
  didCommitment: labelToBytes32(`did:midnight:maintainer:${label}`),
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

  private emptyMaintainerAuthorizationSigner(): MaintainerAuthorizationSigner {
    return {
      keyId: new Uint8Array(32),
      publicKey: { x: 0n, y: 0n },
      signature: {
        announcement: { x: 0n, y: 0n },
        response: 0n,
      },
    };
  }

  private buildMaintainerAuthorizationBundle(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): MaintainerAuthorizationBundle {
    const signers = [
      {
        keyId: maintainerKeyId,
        publicKey: maintainerPublicKey,
        signature,
      },
      ...coAuthorizers,
    ];
    if (signers.length === 0) {
      throw new Error("at least one maintainer authorizer is required");
    }
    if (signers.length > 5) {
      throw new Error("maintainer authorization bundles support at most 5 signers");
    }

    const paddedSigners = [...signers];
    while (paddedSigners.length < 5) {
      paddedSigners.push(this.emptyMaintainerAuthorizationSigner());
    }
    const [signer1, signer2, signer3, signer4, signer5] = paddedSigners as [
      MaintainerAuthorizationSigner,
      MaintainerAuthorizationSigner,
      MaintainerAuthorizationSigner,
      MaintainerAuthorizationSigner,
      MaintainerAuthorizationSigner,
    ];

    return {
      signerCount: BigInt(signers.length),
      signer1,
      signer2,
      signer3,
      signer4,
      signer5,
    };
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
    maintainerId: Uint8Array,
    maintainerDidCommitment: Uint8Array,
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
        maintainerId,
        maintainerDidCommitment,
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeMaintainerAction(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        actionKind,
        actionPayloadHash,
      ),
    );
  }

  updateMaintainerThresholdPolicy(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    defaultThreshold: bigint,
    emergencyThreshold: bigint,
    archivalThreshold: bigint,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.updateMaintainerThresholdPolicy(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        defaultThreshold,
        emergencyThreshold,
        archivalThreshold,
      ),
    );
  }

  proposeMaintainerMembership(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    candidateMaintainerId: Uint8Array,
    candidateDidCommitment: Uint8Array,
    candidateKeyId: Uint8Array,
    candidatePublicKey: JubjubPoint,
    policyId: Uint8Array,
    trustLevel: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.proposeMaintainerMembership(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        candidateMaintainerId,
        candidateDidCommitment,
        candidateKeyId,
        candidatePublicKey,
        policyId,
        trustLevel,
        evidenceHash,
      ),
    );
  }

  authorizeMaintainerMembership(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    candidateMaintainerId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeMaintainerMembership(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        candidateMaintainerId,
        evidenceHash,
      ),
    );
  }

  activateMaintainerMembership(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    candidateMaintainerId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.activateMaintainerMembership(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        candidateMaintainerId,
        evidenceHash,
      ),
    );
  }

  suspendMaintainerMembership(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    candidateMaintainerId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendMaintainerMembership(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        candidateMaintainerId,
        evidenceHash,
      ),
    );
  }

  revokeMaintainerMembership(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    candidateMaintainerId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeMaintainerMembership(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        candidateMaintainerId,
        evidenceHash,
      ),
    );
  }

  archiveMaintainerMembership(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    candidateMaintainerId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.archiveMaintainerMembership(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        candidateMaintainerId,
        evidenceHash,
      ),
    );
  }

  getMaintainerMembership(
    maintainerId: Uint8Array,
  ): MaintainerMembershipRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getMaintainerMembership(
        this.circuitContext,
        maintainerId,
      ),
    );
  }

  getCurrentMaintainerMembership(
    maintainerDidCommitment: Uint8Array,
  ): MaintainerMembershipRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentMaintainerMembership(
        this.circuitContext,
        maintainerDidCommitment,
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.createIssuerAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  proposeIssuerAuthorization(
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.proposeIssuerAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  authorizeIssuerAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeIssuerAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
        evidenceHash,
      ),
    );
  }

  activateIssuerAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.activateIssuerAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendIssuerAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeIssuerAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.archiveIssuerAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.createVerifierAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  proposeVerifierAuthorization(
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.proposeVerifierAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  authorizeVerifierAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeVerifierAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
        evidenceHash,
      ),
    );
  }

  activateVerifierAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.activateVerifierAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendVerifierAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeVerifierAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.archiveVerifierAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.createRecognition(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  proposeRecognition(
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.proposeRecognition(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  authorizeRecognition(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    recognitionId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeRecognition(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        recognitionId,
        evidenceHash,
      ),
    );
  }

  activateRecognition(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    recognitionId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.activateRecognition(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        recognitionId,
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendRecognition(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeRecognition(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.archiveRecognition(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  createAuditorAuthorization(
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.createAuditorAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  proposeAuditorAuthorization(
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
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.proposeAuditorAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
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

  authorizeAuditorAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeAuditorAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
        evidenceHash,
      ),
    );
  }

  activateAuditorAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.activateAuditorAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
        evidenceHash,
      ),
    );
  }

  suspendAuditorAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendAuditorAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
        evidenceHash,
      ),
    );
  }

  revokeAuditorAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeAuditorAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
        evidenceHash,
      ),
    );
  }

  archiveAuditorAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    evidenceHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.archiveAuditorAuthorization(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        authorizationId,
        evidenceHash,
      ),
    );
  }

  getAuditorAuthorization(
    authorizationId: Uint8Array,
  ): AuditorAuthorizationRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getAuditorAuthorization(
        this.circuitContext,
        authorizationId,
      ),
    );
  }

  getCurrentAuditorAuthorization(
    subjectDidCommitment: Uint8Array,
    requestProfileId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): AuditorAuthorizationRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentAuditorAuthorization(
        this.circuitContext,
        subjectDidCommitment,
        requestProfileId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
      ),
    );
  }

  assertAuditorAuthorized(
    subjectDidCommitment: Uint8Array,
    requestProfileId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): void {
    this.executeCircuit(() =>
      this.contract.impureCircuits.assertAuditorAuthorized(
        this.circuitContext,
        subjectDidCommitment,
        requestProfileId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
      ),
    );
  }

  publishEpochCommitment(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    epochId: Uint8Array,
    stateRoot: Uint8Array,
    eventRoot: Uint8Array,
    policyRoot: Uint8Array,
    validFromSequence: bigint,
    validUntilSequence: bigint,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.publishEpochCommitment(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        epochId,
        stateRoot,
        eventRoot,
        policyRoot,
        validFromSequence,
        validUntilSequence,
      ),
    );
  }

  getEpochCommitment(
    epochId: Uint8Array,
  ): EpochCommitmentRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getEpochCommitment(
        this.circuitContext,
        epochId,
      ),
    );
  }

  getCurrentEpochCommitment(): EpochCommitmentRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentEpochCommitment(
        this.circuitContext,
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
