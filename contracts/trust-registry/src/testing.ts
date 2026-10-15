import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

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
  type AuditorProposalEvidenceRecord,
  type EvidenceVerifierKeyRecord,
  type VcAuthorityKeyRecord,
  type EpochCommitmentRecord,
  type IssuerAuthorizationRecord,
  type IssuerProposalEvidenceRecord,
  type MaintainerAuthorizationBundle,
  type MaintainerAuthorizationSigner,
  type MaintainerMembershipRecord,
  type MaintainerProposalEvidenceRecord,
  type RecognitionRecord,
  type RecognitionProposalEvidenceRecord,
  type VerifierAuthorizationRecord,
  type VerifierProposalEvidenceRecord,
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
  if (label.includes("\0")) throw new Error("Fixture labels must not contain NUL bytes");
  for (let index = 0; index < label.length; index += 1) {
    const code = label.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = label.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff || Number.isNaN(next)) {
        throw new Error("Fixture labels must contain valid UTF-16");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error("Fixture labels must contain valid UTF-16");
    }
  }
  const encoded = Buffer.from(label, "utf8");
  // Compact action-kind fixtures keep their short ASCII encoding; long labels get distinct test-only digests.
  if (encoded.length > 32) {
    return new Uint8Array(createHash("sha256")
      .update("tr:test-fixture-label:v1\0")
      .update(encoded)
      .digest());
  }
  const bytes = new Uint8Array(32);
  bytes.set(encoded);
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

export type TrustRegistryBootstrapConfig = {
  registryId: Uint8Array;
  registryDidCommitment: Uint8Array;
  governancePolicyCommitment: Uint8Array;
  maintainerId: Uint8Array;
  maintainerDidCommitment: Uint8Array;
  maintainerKeyId: Uint8Array;
  maintainerPublicKey: JubjubPoint;
  maintainerThreshold: bigint;
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
  readonly contractAddress = sampleContractAddress();
  circuitContext: CircuitContext<TrustRegistryPrivateState>;

  constructor(bootstrap: TrustRegistryBootstrapConfig) {
    this.contract = new Contract<TrustRegistryPrivateState>(
      trustRegistryWitnesses,
    );
    const initialState = this.contract.initialState(
      createConstructorContext({}, "0".repeat(64)),
      bootstrap.registryId,
      bootstrap.registryDidCommitment,
      bootstrap.governancePolicyCommitment,
      bootstrap.maintainerId,
      bootstrap.maintainerDidCommitment,
      bootstrap.maintainerKeyId,
      bootstrap.maintainerPublicKey,
      bootstrap.maintainerThreshold,
    );
    this.circuitContext = createCircuitContext(
      this.contractAddress,
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
      this.contractAddress,
      result.context.currentZswapLocalState,
      result.context.currentQueryContext.state,
      result.context.currentPrivateState,
    );
    return result.result;
  }

  authorizeMaintainerAuditEvent(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    actionPayloadHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.authorizeMaintainerAuditEvent(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        actionPayloadHash,
      ),
    );
  }

  updateMaintainerThresholdPolicy(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    nextPolicyCommitment: Uint8Array,
    nextPolicyVersion: bigint,
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
        nextPolicyCommitment,
        nextPolicyVersion,
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
    evidenceVerifierAuthorizationId: Uint8Array,
    evidenceVerifierKeyIdCommitment: Uint8Array,
    evidenceSignature: { announcement: JubjubPoint; response: bigint },
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
        evidenceVerifierAuthorizationId,
        evidenceVerifierKeyIdCommitment,
        evidenceSignature,
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

  getMaintainerProposalEvidence(
    maintainerId: Uint8Array,
  ): MaintainerProposalEvidenceRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getMaintainerProposalEvidence(
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

  registerVcAuthorityKey(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    keyIdCommitment: Uint8Array,
    authorityDidCommitment: Uint8Array,
    authorityMethodIdCommitment: Uint8Array,
    publicKey: JubjubPoint,
    networkIdCommitment: Uint8Array,
    consumerContractAddress: Uint8Array,
    policyCommitment: Uint8Array,
    policyVersion: bigint,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.registerVcAuthorityKey(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId, maintainerPublicKey, signature, coAuthorizers,
        ),
        keyIdCommitment,
        authorityDidCommitment,
        authorityMethodIdCommitment,
        publicKey,
        networkIdCommitment,
        consumerContractAddress,
        policyCommitment,
        policyVersion,
      ),
    );
  }

  getVcAuthorityKey(keyIdCommitment: Uint8Array): VcAuthorityKeyRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getVcAuthorityKey(this.circuitContext, keyIdCommitment),
    );
  }

  getCurrentVcAuthorityKey(consumerContractAddress: Uint8Array): VcAuthorityKeyRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentVcAuthorityKey(
        this.circuitContext, consumerContractAddress,
      ),
    );
  }

  suspendVcAuthorityKey(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    keyIdCommitment: Uint8Array,
    reasonHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendVcAuthorityKey(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId, maintainerPublicKey, signature, coAuthorizers,
        ),
        keyIdCommitment,
        reasonHash,
      ),
    );
  }

  revokeVcAuthorityKey(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    keyIdCommitment: Uint8Array,
    reasonHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeVcAuthorityKey(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId, maintainerPublicKey, signature, coAuthorizers,
        ),
        keyIdCommitment,
        reasonHash,
      ),
    );
  }

  rotateVcAuthorityKey(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    oldKeyIdCommitment: Uint8Array,
    newKeyIdCommitment: Uint8Array,
    newAuthorityMethodIdCommitment: Uint8Array,
    newPublicKey: JubjubPoint,
    reasonHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.rotateVcAuthorityKey(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId, maintainerPublicKey, signature, coAuthorizers,
        ),
        oldKeyIdCommitment,
        newKeyIdCommitment,
        newAuthorityMethodIdCommitment,
        newPublicKey,
        reasonHash,
      ),
    );
  }

  registerEvidenceVerifierKey(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    didCommitment: Uint8Array,
    keyIdCommitment: Uint8Array,
    publicKey: JubjubPoint,
    suite: Uint8Array,
    policyCommitment: Uint8Array,
    policyVersion: bigint,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.registerEvidenceVerifierKey(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId, maintainerPublicKey, signature, coAuthorizers,
        ),
        authorizationId,
        didCommitment,
        keyIdCommitment,
        publicKey,
        suite,
        policyCommitment,
        policyVersion,
      ),
    );
  }

  suspendEvidenceVerifierKey(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    reasonHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.suspendEvidenceVerifierKey(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId, maintainerPublicKey, signature, coAuthorizers,
        ),
        authorizationId,
        reasonHash,
      ),
    );
  }

  revokeEvidenceVerifierKey(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    reasonHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.revokeEvidenceVerifierKey(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId, maintainerPublicKey, signature, coAuthorizers,
        ),
        authorizationId,
        reasonHash,
      ),
    );
  }

  rotateEvidenceVerifierKey(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    oldAuthorizationId: Uint8Array,
    newAuthorizationId: Uint8Array,
    newKeyIdCommitment: Uint8Array,
    newPublicKey: JubjubPoint,
    reasonHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Uint8Array {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.rotateEvidenceVerifierKey(
        this.circuitContext,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId, maintainerPublicKey, signature, coAuthorizers,
        ),
        oldAuthorizationId,
        newAuthorizationId,
        newKeyIdCommitment,
        newPublicKey,
        reasonHash,
      ),
    );
  }

  getEvidenceVerifierKey(authorizationId: Uint8Array): EvidenceVerifierKeyRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getEvidenceVerifierKey(
        this.circuitContext,
        authorizationId,
      ),
    );
  }

  getIssuerProposalEvidence(authorizationId: Uint8Array): IssuerProposalEvidenceRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getIssuerProposalEvidence(
        this.circuitContext,
        authorizationId,
      ),
    );
  }

  getVerifierProposalEvidence(authorizationId: Uint8Array): VerifierProposalEvidenceRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getVerifierProposalEvidence(
        this.circuitContext,
        authorizationId,
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
    statusPolicyBindingCommitment: Uint8Array,
    trustLevel: Uint8Array,
    evidenceHash: Uint8Array,
    evidenceVerifierAuthorizationId: Uint8Array,
    evidenceVerifierKeyIdCommitment: Uint8Array,
    evidenceSignature: { announcement: JubjubPoint; response: bigint },
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
        statusPolicyBindingCommitment,
        trustLevel,
        evidenceHash,
        evidenceVerifierAuthorizationId,
        evidenceVerifierKeyIdCommitment,
        evidenceSignature,
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

  proposeVerifierAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    subjectDidCommitment: Uint8Array,
    requestResourceId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
    policyId: Uint8Array,
    trustLevel: Uint8Array,
    evidenceHash: Uint8Array,
    evidenceVerifierAuthorizationId: Uint8Array,
    evidenceVerifierKeyIdCommitment: Uint8Array,
    evidenceSignature: { announcement: JubjubPoint; response: bigint },
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
        requestResourceId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
        policyId,
        trustLevel,
        evidenceHash,
        evidenceVerifierAuthorizationId,
        evidenceVerifierKeyIdCommitment,
        evidenceSignature,
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
    requestResourceId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): VerifierAuthorizationRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentVerifierAuthorization(
        this.circuitContext,
        subjectDidCommitment,
        requestResourceId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
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
    evidenceVerifierAuthorizationId: Uint8Array,
    evidenceVerifierKeyIdCommitment: Uint8Array,
    evidenceSignature: { announcement: JubjubPoint; response: bigint },
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
        evidenceVerifierAuthorizationId,
        evidenceVerifierKeyIdCommitment,
        evidenceSignature,
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

  getRecognitionProposalEvidence(
    recognitionId: Uint8Array,
  ): RecognitionProposalEvidenceRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getRecognitionProposalEvidence(
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

  proposeAuditorAuthorization(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    authorizationId: Uint8Array,
    subjectDidCommitment: Uint8Array,
    requestResourceId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
    policyId: Uint8Array,
    trustLevel: Uint8Array,
    evidenceHash: Uint8Array,
    evidenceVerifierAuthorizationId: Uint8Array,
    evidenceVerifierKeyIdCommitment: Uint8Array,
    evidenceSignature: { announcement: JubjubPoint; response: bigint },
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
        requestResourceId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
        policyId,
        trustLevel,
        evidenceHash,
        evidenceVerifierAuthorizationId,
        evidenceVerifierKeyIdCommitment,
        evidenceSignature,
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

  getAuditorProposalEvidence(
    authorizationId: Uint8Array,
  ): AuditorProposalEvidenceRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getAuditorProposalEvidence(
        this.circuitContext,
        authorizationId,
      ),
    );
  }

  getCurrentAuditorAuthorization(
    subjectDidCommitment: Uint8Array,
    requestResourceId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): AuditorAuthorizationRecord {
    return this.executeCircuit(() =>
      this.contract.impureCircuits.getCurrentAuditorAuthorization(
        this.circuitContext,
        subjectDidCommitment,
        requestResourceId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
      ),
    );
  }

  assertAuditorAuthorized(
    subjectDidCommitment: Uint8Array,
    requestResourceId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): void {
    this.executeCircuit(() =>
      this.contract.impureCircuits.assertAuditorAuthorized(
        this.circuitContext,
        subjectDidCommitment,
        requestResourceId,
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
    requestResourceId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): void {
    this.executeCircuit(() =>
      this.contract.impureCircuits.assertVerifierAuthorized(
        this.circuitContext,
        subjectDidCommitment,
        requestResourceId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
      ),
    );
  }
}
