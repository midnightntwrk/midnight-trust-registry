import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import {
  type CircuitContext,
  type CircuitResults,
  type ContractAddress,
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
import { buildCanonicalMaintainerAuthorizationBundle } from "./signing.js";

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
  networkIdCommitment: Uint8Array;
  contractAddress?: ContractAddress;
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
  readonly contractAddress: ContractAddress;
  circuitContext!: CircuitContext<TrustRegistryPrivateState>;
  readonly ready: Promise<void>;
  private queue: Promise<void>;

  constructor(bootstrap: TrustRegistryBootstrapConfig) {
    if (bootstrap.contractAddress !== undefined
      && (!/^[0-9a-f]{64}$/u.test(bootstrap.contractAddress)
        || /^0{64}$/u.test(bootstrap.contractAddress))) {
      throw new RangeError("Simulator contract address must be a nonzero 32-byte hex value");
    }
    this.contractAddress = bootstrap.contractAddress ?? sampleContractAddress();
    this.contract = new Contract<TrustRegistryPrivateState>(
      trustRegistryWitnesses,
    );
    this.ready = this.contract.initialState(
      createConstructorContext({}, "0".repeat(64)),
      bootstrap.registryId,
      bootstrap.registryDidCommitment,
      bootstrap.governancePolicyCommitment,
      bootstrap.maintainerId,
      bootstrap.maintainerDidCommitment,
      bootstrap.maintainerKeyId,
      bootstrap.maintainerPublicKey,
      bootstrap.maintainerThreshold,
      bootstrap.networkIdCommitment,
    ).then((initialState) => {
      this.circuitContext = createCircuitContext({
        circuitId: "constructor",
        contractAddress: this.contractAddress,
        coinPublicKeyOrZswapState: initialState.currentZswapLocalState,
        contractState: initialState.currentContractState,
        privateState: initialState.currentPrivateState,
      });
    });
    this.queue = this.ready;
  }

  async getLedger(): Promise<Ledger> {
    await this.ready;
    await this.queue;
    return ledger(this.circuitContext.callContext.currentQueryContext.state);
  }

  private buildMaintainerAuthorizationBundle(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): MaintainerAuthorizationBundle {
    return buildCanonicalMaintainerAuthorizationBundle([
      {
        keyId: maintainerKeyId,
        publicKey: maintainerPublicKey,
        signature,
      },
      ...coAuthorizers,
    ]);
  }

  private executeCircuit<T>(
    circuitId: string,
    circuitFn: (context: CircuitContext<TrustRegistryPrivateState>) => Promise<CircuitResults<TrustRegistryPrivateState, T>>,
  ): Promise<T> {
    const operation = this.queue.then(async () => {
      await this.ready;
      const previous = this.circuitContext.callContext;
      if (previous.currentZswapLocalState === undefined || previous.currentPrivateState === undefined) {
        throw new Error("Simulator state is incomplete");
      }
      const context = createCircuitContext({
        circuitId,
        contractAddress: this.contractAddress,
        coinPublicKeyOrZswapState: previous.currentZswapLocalState,
        contractState: previous.currentQueryContext.state,
        privateState: previous.currentPrivateState,
      });
      const result = await circuitFn(context);
      this.circuitContext = result.context;
      return result.result;
    });
    this.queue = operation.then(() => undefined, () => undefined);
    return operation;
  }

  authorizeMaintainerAuditEvent(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    actionPayloadHash: Uint8Array,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Promise<Uint8Array> {
    return this.executeCircuit("authorizeMaintainerAuditEvent", (context) =>
      this.contract.impureCircuits.authorizeMaintainerAuditEvent(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("updateMaintainerThresholdPolicy", (context) =>
      this.contract.impureCircuits.updateMaintainerThresholdPolicy(
        context,
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

  recoverMaintainerMembership(
    maintainerKeyId: Uint8Array,
    maintainerPublicKey: JubjubPoint,
    signature: { announcement: JubjubPoint; response: bigint },
    candidateMaintainerId: Uint8Array,
    evidenceHash: Uint8Array,
    nextPolicyCommitment: Uint8Array,
    nextPolicyVersion: bigint,
    defaultThreshold: bigint,
    emergencyThreshold: bigint,
    archivalThreshold: bigint,
    coAuthorizers: readonly MaintainerCoAuthorizer[] = [],
  ): Promise<Uint8Array> {
    return this.executeCircuit("recoverMaintainerMembership", (context) =>
      this.contract.impureCircuits.recoverMaintainerMembership(
        context,
        this.buildMaintainerAuthorizationBundle(
          maintainerKeyId,
          maintainerPublicKey,
          signature,
          coAuthorizers,
        ),
        candidateMaintainerId,
        evidenceHash,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("proposeMaintainerMembership", (context) =>
      this.contract.impureCircuits.proposeMaintainerMembership(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("authorizeMaintainerMembership", (context) =>
      this.contract.impureCircuits.authorizeMaintainerMembership(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("activateMaintainerMembership", (context) =>
      this.contract.impureCircuits.activateMaintainerMembership(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("suspendMaintainerMembership", (context) =>
      this.contract.impureCircuits.suspendMaintainerMembership(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("revokeMaintainerMembership", (context) =>
      this.contract.impureCircuits.revokeMaintainerMembership(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("archiveMaintainerMembership", (context) =>
      this.contract.impureCircuits.archiveMaintainerMembership(
        context,
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
  ): Promise<MaintainerMembershipRecord> {
    return this.executeCircuit("getMaintainerMembership", (context) =>
      this.contract.impureCircuits.getMaintainerMembership(
        context,
        maintainerId,
      ),
    );
  }

  getMaintainerProposalEvidence(
    maintainerId: Uint8Array,
  ): Promise<MaintainerProposalEvidenceRecord> {
    return this.executeCircuit("getMaintainerProposalEvidence", (context) =>
      this.contract.impureCircuits.getMaintainerProposalEvidence(
        context,
        maintainerId,
      ),
    );
  }

  getCurrentMaintainerMembership(
    maintainerDidCommitment: Uint8Array,
  ): Promise<MaintainerMembershipRecord> {
    return this.executeCircuit("getCurrentMaintainerMembership", (context) =>
      this.contract.impureCircuits.getCurrentMaintainerMembership(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("registerVcAuthorityKey", (context) =>
      this.contract.impureCircuits.registerVcAuthorityKey(
        context,
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

  getVcAuthorityKey(keyIdCommitment: Uint8Array): Promise<VcAuthorityKeyRecord> {
    return this.executeCircuit("getVcAuthorityKey", (context) =>
      this.contract.impureCircuits.getVcAuthorityKey(context, keyIdCommitment),
    );
  }

  getCurrentVcAuthorityKey(consumerContractAddress: Uint8Array): Promise<VcAuthorityKeyRecord> {
    return this.executeCircuit("getCurrentVcAuthorityKey", (context) =>
      this.contract.impureCircuits.getCurrentVcAuthorityKey(
        context, consumerContractAddress,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("suspendVcAuthorityKey", (context) =>
      this.contract.impureCircuits.suspendVcAuthorityKey(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("revokeVcAuthorityKey", (context) =>
      this.contract.impureCircuits.revokeVcAuthorityKey(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("rotateVcAuthorityKey", (context) =>
      this.contract.impureCircuits.rotateVcAuthorityKey(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("registerEvidenceVerifierKey", (context) =>
      this.contract.impureCircuits.registerEvidenceVerifierKey(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("suspendEvidenceVerifierKey", (context) =>
      this.contract.impureCircuits.suspendEvidenceVerifierKey(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("revokeEvidenceVerifierKey", (context) =>
      this.contract.impureCircuits.revokeEvidenceVerifierKey(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("rotateEvidenceVerifierKey", (context) =>
      this.contract.impureCircuits.rotateEvidenceVerifierKey(
        context,
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

  getEvidenceVerifierKey(authorizationId: Uint8Array): Promise<EvidenceVerifierKeyRecord> {
    return this.executeCircuit("getEvidenceVerifierKey", (context) =>
      this.contract.impureCircuits.getEvidenceVerifierKey(
        context,
        authorizationId,
      ),
    );
  }

  getIssuerProposalEvidence(authorizationId: Uint8Array): Promise<IssuerProposalEvidenceRecord> {
    return this.executeCircuit("getIssuerProposalEvidence", (context) =>
      this.contract.impureCircuits.getIssuerProposalEvidence(
        context,
        authorizationId,
      ),
    );
  }

  getVerifierProposalEvidence(authorizationId: Uint8Array): Promise<VerifierProposalEvidenceRecord> {
    return this.executeCircuit("getVerifierProposalEvidence", (context) =>
      this.contract.impureCircuits.getVerifierProposalEvidence(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("proposeIssuerAuthorization", (context) =>
      this.contract.impureCircuits.proposeIssuerAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("authorizeIssuerAuthorization", (context) =>
      this.contract.impureCircuits.authorizeIssuerAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("activateIssuerAuthorization", (context) =>
      this.contract.impureCircuits.activateIssuerAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("suspendIssuerAuthorization", (context) =>
      this.contract.impureCircuits.suspendIssuerAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("revokeIssuerAuthorization", (context) =>
      this.contract.impureCircuits.revokeIssuerAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("archiveIssuerAuthorization", (context) =>
      this.contract.impureCircuits.archiveIssuerAuthorization(
        context,
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
  ): Promise<IssuerAuthorizationRecord> {
    return this.executeCircuit("getIssuerAuthorization", (context) =>
      this.contract.impureCircuits.getIssuerAuthorization(
        context,
        authorizationId,
      ),
    );
  }

  getCurrentIssuerAuthorization(
    subjectDidCommitment: Uint8Array,
    resourceType: IssuerResourceType,
    resourceId: Uint8Array,
  ): Promise<IssuerAuthorizationRecord> {
    return this.executeCircuit("getCurrentIssuerAuthorization", (context) =>
      this.contract.impureCircuits.getCurrentIssuerAuthorization(
        context,
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
  ): Promise<void> {
    return this.executeCircuit("assertIssuerAuthorized", (context) =>
      this.contract.impureCircuits.assertIssuerAuthorized(
        context,
        subjectDidCommitment,
        resourceType,
        resourceId,
      ),
    ).then(() => undefined);
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("proposeVerifierAuthorization", (context) =>
      this.contract.impureCircuits.proposeVerifierAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("authorizeVerifierAuthorization", (context) =>
      this.contract.impureCircuits.authorizeVerifierAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("activateVerifierAuthorization", (context) =>
      this.contract.impureCircuits.activateVerifierAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("suspendVerifierAuthorization", (context) =>
      this.contract.impureCircuits.suspendVerifierAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("revokeVerifierAuthorization", (context) =>
      this.contract.impureCircuits.revokeVerifierAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("archiveVerifierAuthorization", (context) =>
      this.contract.impureCircuits.archiveVerifierAuthorization(
        context,
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
  ): Promise<VerifierAuthorizationRecord> {
    return this.executeCircuit("getVerifierAuthorization", (context) =>
      this.contract.impureCircuits.getVerifierAuthorization(
        context,
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
  ): Promise<VerifierAuthorizationRecord> {
    return this.executeCircuit("getCurrentVerifierAuthorization", (context) =>
      this.contract.impureCircuits.getCurrentVerifierAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("proposeRecognition", (context) =>
      this.contract.impureCircuits.proposeRecognition(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("authorizeRecognition", (context) =>
      this.contract.impureCircuits.authorizeRecognition(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("activateRecognition", (context) =>
      this.contract.impureCircuits.activateRecognition(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("suspendRecognition", (context) =>
      this.contract.impureCircuits.suspendRecognition(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("revokeRecognition", (context) =>
      this.contract.impureCircuits.revokeRecognition(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("archiveRecognition", (context) =>
      this.contract.impureCircuits.archiveRecognition(
        context,
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
  ): Promise<RecognitionRecord> {
    return this.executeCircuit("getRecognition", (context) =>
      this.contract.impureCircuits.getRecognition(
        context,
        recognitionId,
      ),
    );
  }

  getRecognitionProposalEvidence(
    recognitionId: Uint8Array,
  ): Promise<RecognitionProposalEvidenceRecord> {
    return this.executeCircuit("getRecognitionProposalEvidence", (context) =>
      this.contract.impureCircuits.getRecognitionProposalEvidence(
        context,
        recognitionId,
      ),
    );
  }

  getCurrentRecognition(
    recognizedAuthorityDidCommitment: Uint8Array,
    recognizedRegistryId: Uint8Array,
    scopeResourceType: Uint8Array,
    scopeResourceId: Uint8Array,
  ): Promise<RecognitionRecord> {
    return this.executeCircuit("getCurrentRecognition", (context) =>
      this.contract.impureCircuits.getCurrentRecognition(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("proposeAuditorAuthorization", (context) =>
      this.contract.impureCircuits.proposeAuditorAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("authorizeAuditorAuthorization", (context) =>
      this.contract.impureCircuits.authorizeAuditorAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("activateAuditorAuthorization", (context) =>
      this.contract.impureCircuits.activateAuditorAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("suspendAuditorAuthorization", (context) =>
      this.contract.impureCircuits.suspendAuditorAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("revokeAuditorAuthorization", (context) =>
      this.contract.impureCircuits.revokeAuditorAuthorization(
        context,
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("archiveAuditorAuthorization", (context) =>
      this.contract.impureCircuits.archiveAuditorAuthorization(
        context,
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
  ): Promise<AuditorAuthorizationRecord> {
    return this.executeCircuit("getAuditorAuthorization", (context) =>
      this.contract.impureCircuits.getAuditorAuthorization(
        context,
        authorizationId,
      ),
    );
  }

  getAuditorProposalEvidence(
    authorizationId: Uint8Array,
  ): Promise<AuditorProposalEvidenceRecord> {
    return this.executeCircuit("getAuditorProposalEvidence", (context) =>
      this.contract.impureCircuits.getAuditorProposalEvidence(
        context,
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
  ): Promise<AuditorAuthorizationRecord> {
    return this.executeCircuit("getCurrentAuditorAuthorization", (context) =>
      this.contract.impureCircuits.getCurrentAuditorAuthorization(
        context,
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
  ): Promise<void> {
    return this.executeCircuit("assertAuditorAuthorized", (context) =>
      this.contract.impureCircuits.assertAuditorAuthorized(
        context,
        subjectDidCommitment,
        requestResourceId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
      ),
    ).then(() => undefined);
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
  ): Promise<Uint8Array> {
    return this.executeCircuit("publishEpochCommitment", (context) =>
      this.contract.impureCircuits.publishEpochCommitment(
        context,
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
  ): Promise<EpochCommitmentRecord> {
    return this.executeCircuit("getEpochCommitment", (context) =>
      this.contract.impureCircuits.getEpochCommitment(
        context,
        epochId,
      ),
    );
  }

  getCurrentEpochCommitment(): Promise<EpochCommitmentRecord> {
    return this.executeCircuit("getCurrentEpochCommitment", (context) =>
      this.contract.impureCircuits.getCurrentEpochCommitment(
        context,
      ),
    );
  }

  assertRecognitionActive(
    recognizedAuthorityDidCommitment: Uint8Array,
    recognizedRegistryId: Uint8Array,
    scopeResourceType: Uint8Array,
    scopeResourceId: Uint8Array,
  ): Promise<void> {
    return this.executeCircuit("assertRecognitionActive", (context) =>
      this.contract.impureCircuits.assertRecognitionActive(
        context,
        recognizedAuthorityDidCommitment,
        recognizedRegistryId,
        scopeResourceType,
        scopeResourceId,
      ),
    ).then(() => undefined);
  }

  assertVerifierAuthorized(
    subjectDidCommitment: Uint8Array,
    requestResourceId: Uint8Array,
    allowedAttributeSetCommitment: Uint8Array,
    allowedPredicateSetCommitment: Uint8Array,
    disclosureLevelCommitment: Uint8Array,
  ): Promise<void> {
    return this.executeCircuit("assertVerifierAuthorized", (context) =>
      this.contract.impureCircuits.assertVerifierAuthorized(
        context,
        subjectDidCommitment,
        requestResourceId,
        allowedAttributeSetCommitment,
        allowedPredicateSetCommitment,
        disclosureLevelCommitment,
      ),
    ).then(() => undefined);
  }
}
