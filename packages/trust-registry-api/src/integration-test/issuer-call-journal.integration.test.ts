import { Buffer } from "node:buffer";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import {
  EvidenceVerifierKeyStatus,
  MaintainerStatus,
  TrustRegistryContract,
  computeCreateIssuerAuthorizationPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  signDeploymentBoundMaintainerActionFromSeed,
  signIssuerProposalEvidenceFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  prepareLocalIssuerProposalCall,
  submitLocalIssuerProposalCall,
  type LocalIssuerProposalCall,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  FileProposalSubmissionJournal,
  ProposalSubmissionAlreadyPendingError,
  ProposalSubmissionConflictError,
  ProposalSubmissionOutcomeUnknownError,
} from "../proposal-submission-journal.js";

const mocks = vi.hoisted(() => ({ submitCallTx: vi.fn() }));
vi.mock("@midnight-ntwrk/midnight-js-contracts", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/midnight-js-contracts")>(),
  submitCallTx: mocks.submitCallTx,
}));

const registryLabel = "registry:issuer-journal";
const authorizationLabel = "issuer:issuer-journal";
const contractAddress = `0x${"a".repeat(64)}`;
const genesisHash = `0x${"d".repeat(64)}`;
const maintainerSeed = new Uint8Array(32).fill(13);
const verifierSeed = new Uint8Array(32).fill(19);

function fixture(): { call: LocalIssuerProposalCall; ledger: TrustRegistryContract.Ledger } {
  const registryId = bytes32Commitment(registryLabel);
  const authorizationId = bytes32Commitment(authorizationLabel);
  const subjectDidCommitment = bytes32Commitment("did:midnight:undeployed:issuer-journal");
  const resourceId = bytes32Commitment("credential-family:issuer-journal");
  const policyId = bytes32Commitment("policy:issuer-journal");
  const statusPolicyBindingCommitment = bytes32Commitment("status:issuer-journal");
  const trustLevel = bytes32Commitment("trust-level:issuer-journal");
  const evidenceHash = bytes32Commitment("accepted-vp:issuer-journal");
  const evidenceVerifierAuthorizationId = bytes32Commitment("verifier:issuer-journal");
  const evidenceVerifierKeyIdCommitment = bytes32Commitment("verifier-key:issuer-journal");
  const keyId = bytes32Commitment("maintainer-key:issuer-journal");
  const networkId = bytes32Commitment("undeployed");
  const resourceType = TrustRegistryContract.IssuerResourceType.credentialFamily;
  const actionPayloadHash = computeIssuerEvidenceBoundProposalPayloadHash(
    computeCreateIssuerAuthorizationPayloadHash(
      authorizationId, subjectDidCommitment, resourceType, resourceId, policyId,
      statusPolicyBindingCommitment, trustLevel, evidenceHash,
    ),
    evidenceVerifierAuthorizationId, evidenceVerifierKeyIdCommitment, policyId, 1n,
  );
  const verifierDidCommitment = bytes32Commitment("did:midnight:undeployed:verifier-journal");
  const keyScope = TrustRegistryContract.pureCircuits.evidenceVerifierKeyScopeKey(
    verifierDidCommitment, policyId,
  );
  const suite = new Uint8Array(32);
  suite.set(new TextEncoder().encode("jubjub-schnorr"));
  const ledger = {
    initialized: true, contractVersion: 1n, registryId, deploymentNetworkIdCommitment: networkId,
    governancePolicyCommitment: policyId, governancePolicyVersion: 1n, governanceActionCount: 3n,
    maintainerThreshold: 1n, emergencyMaintainerThreshold: 1n, archivalMaintainerThreshold: 1n,
    maintainerKeyIds: { member: (id: Uint8Array) => Buffer.from(id).equals(Buffer.from(keyId)) },
    maintainerRecords: { lookup: () => ({
      keyId, publicKey: deriveJubjubPublicKeyFromSeed(maintainerSeed), status: MaintainerStatus.active,
    }) },
    issuerAuthorizationIds: { member: () => false },
    issuerProposalEvidenceRecords: { member: () => false },
    currentIssuerAuthorizationIdsByScopeKey: { member: () => false },
    evidenceVerifierKeyRecords: {
      member: (id: Uint8Array) => Buffer.from(id).equals(Buffer.from(evidenceVerifierAuthorizationId)),
      lookup: () => ({
        authorizationId: evidenceVerifierAuthorizationId, keyIdCommitment: evidenceVerifierKeyIdCommitment,
        verifierDidCommitment, publicKey: deriveJubjubPublicKeyFromSeed(verifierSeed),
        status: EvidenceVerifierKeyStatus.active, suite, policyCommitment: policyId, policyVersion: 1n,
      }),
    },
    currentEvidenceVerifierKeyIdsByScopeKey: {
      member: (scope: Uint8Array) => Buffer.from(scope).equals(Buffer.from(keyScope)),
      lookup: () => evidenceVerifierAuthorizationId,
    },
  } as unknown as TrustRegistryContract.Ledger;
  const call: LocalIssuerProposalCall = {
    networkId: "undeployed", registryId: registryLabel, contractAddress,
    authorizationLabel, authorizationId, subjectDidCommitment, resourceType, resourceId,
    policyId, statusPolicyBindingCommitment, trustLevel, evidenceHash,
    evidenceVerifierAuthorizationId, evidenceVerifierKeyIdCommitment,
    evidenceVerifierSignature: signIssuerProposalEvidenceFromSeed(
      verifierSeed, registryId, networkId, Buffer.from(contractAddress.slice(2), "hex"),
      evidenceVerifierKeyIdCommitment, actionPayloadHash,
    ),
    signers: [{
      keyId, publicKey: deriveJubjubPublicKeyFromSeed(maintainerSeed),
      signature: signDeploymentBoundMaintainerActionFromSeed(
        maintainerSeed, registryId, networkId, Buffer.from(contractAddress.slice(2), "hex"),
        policyId, encodeCompactActionKind("tr:issuer:propose"), actionPayloadHash, 3n,
      ),
    }],
  };
  return { call, ledger };
}

describe("issuer SDK handoff with private journal", () => {
  let directory: string;
  let path: string;

  beforeEach(async () => {
    setNetworkId("undeployed");
    mocks.submitCallTx.mockReset();
    directory = await mkdtemp(join(tmpdir(), "tr-issuer-call-journal-"));
    path = join(directory, "journal.json");
  });
  afterEach(async () => { await rm(directory, { recursive: true, force: true }); });

  const input = (journal: FileProposalSubmissionJournal) => {
    const { call, ledger } = fixture();
    return {
      call, expectedGenesisHash: genesisHash,
      readFinalizedLedger: async (address: string) => ({ contractAddress: address, genesisHash, ledger }),
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"],
      readSubmissionProviderIdentity: async () => ({ contractAddress, genesisHash }),
      journal,
    };
  };

  it("persists one SDK result and rejects replay after restart", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registryLabel, contractAddress, genesisHash);
    const request = input(journal);
    const prepared = prepareLocalIssuerProposalCall(request.call,
      (await request.readFinalizedLedger(contractAddress)).ledger);
    const eventHash = `0x${Buffer.from(prepared.expectedEventHash).toString("hex")}`;
    const reservationContext = {
      actionSequence: prepared.actionSequence.toString(),
      actionKind: `0x${Buffer.from(prepared.actionKind).toString("hex")}`,
      actionPayloadHash: `0x${Buffer.from(prepared.actionPayloadHash).toString("hex")}`,
    };
    mocks.submitCallTx.mockResolvedValueOnce({
      private: { result: Buffer.from(eventHash.slice(2), "hex") }, public: { txId: "tx-issuer-journal" },
    });
    await expect(submitLocalIssuerProposalCall(request)).resolves.toEqual({ eventHash });
    expect(await journal.read("issuer", authorizationLabel)).toMatchObject({
      state: "submitted", eventHash, reservationContext,
    });
    expect(await readFile(path, "utf8")).not.toContain("tx-issuer-journal");

    const reopened = new FileProposalSubmissionJournal(path);
    expect(await reopened.read("issuer", authorizationLabel)).toMatchObject({ reservationContext });
    await expect(submitLocalIssuerProposalCall(input(reopened)))
      .rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect(mocks.submitCallTx).toHaveBeenCalledOnce();
  });

  it("holds an ambiguous SDK response across restart without a second submission", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registryLabel, contractAddress, genesisHash);
    mocks.submitCallTx.mockRejectedValueOnce(new Error("response lost after broadcast"));
    await expect(submitLocalIssuerProposalCall(input(journal)))
      .rejects.toBeInstanceOf(ProposalSubmissionOutcomeUnknownError);
    expect(await journal.read("issuer", authorizationLabel)).toMatchObject({
      state: "reserved", eventHash: null,
      reservationContext: {
        actionSequence: "3",
        actionKind: `0x${Buffer.from(encodeCompactActionKind("tr:issuer:propose")).toString("hex")}`,
      },
    });

    const reopened = new FileProposalSubmissionJournal(path);
    expect((await reopened.read("issuer", authorizationLabel))?.reservationContext).toBeDefined();
    await expect(submitLocalIssuerProposalCall(input(reopened)))
      .rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect(mocks.submitCallTx).toHaveBeenCalledOnce();
  });

  it("never enters the SDK when the durable reservation cannot be written", async () => {
    const unavailable = new FileProposalSubmissionJournal(join(directory, "missing", "journal.json"));
    await expect(submitLocalIssuerProposalCall(input(unavailable))).rejects.toThrow();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it("retains an ambiguous attempt until finalized reconciliation, then blocks replay after reopen", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registryLabel, contractAddress, genesisHash);
    const request = input(journal);
    const prepared = prepareLocalIssuerProposalCall(request.call,
      (await request.readFinalizedLedger(contractAddress)).ledger);
    const eventHash = `0x${Buffer.from(prepared.expectedEventHash).toString("hex")}`;
    const evidenceCommitment = `0x${Buffer.from(request.call.evidenceHash).toString("hex")}`;
    mocks.submitCallTx.mockRejectedValueOnce(new Error("response lost after broadcast"));
    await expect(submitLocalIssuerProposalCall(request))
      .rejects.toBeInstanceOf(ProposalSubmissionOutcomeUnknownError);

    const restarted = new FileProposalSubmissionJournal(path);
    await restarted.assertDeploymentBinding(registryLabel, contractAddress, genesisHash);
    expect((await restarted.reconcile("issuer", authorizationLabel, async () => null)).state)
      .toBe("reserved");
    await expect(submitLocalIssuerProposalCall(input(restarted)))
      .rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect((await restarted.reconcile("issuer", authorizationLabel,
      async () => ({ eventHash, evidenceCommitment }))).state).toBe("observed");

    const reopened = new FileProposalSubmissionJournal(path);
    await reopened.assertDeploymentBinding(registryLabel, contractAddress, genesisHash);
    expect(await reopened.read("issuer", authorizationLabel)).toMatchObject({
      state: "observed", eventHash, evidenceCommitment,
    });
    await expect(submitLocalIssuerProposalCall(input(reopened)))
      .rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect(mocks.submitCallTx).toHaveBeenCalledOnce();
  });

  it("rejects a journal bound to another genesis before reading or reserving", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registryLabel, contractAddress, `0x${"e".repeat(64)}`);
    const request = input(journal);
    const readFinalizedLedger = vi.fn(request.readFinalizedLedger);
    await expect(submitLocalIssuerProposalCall({ ...request, readFinalizedLedger }))
      .rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    expect(readFinalizedLedger).not.toHaveBeenCalled();
    expect(await journal.read("issuer", authorizationLabel)).toBeNull();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it("does not reserve when the submitting providers report another genesis", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registryLabel, contractAddress, genesisHash);
    const request = input(journal);
    await expect(submitLocalIssuerProposalCall({
      ...request,
      readSubmissionProviderIdentity: async () => ({ contractAddress, genesisHash: `0x${"e".repeat(64)}` }),
    })).rejects.toThrow(/providers do not match/u);
    expect(await journal.read("issuer", authorizationLabel)).toBeNull();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it.each([
    ["contract", { contractAddress: `0x${"b".repeat(64)}`, genesisHash }],
    ["genesis", { contractAddress, genesisHash: `0x${"e".repeat(64)}` }],
  ])("does not reserve when the finalized reader reports another %s", async (_name, identity) => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registryLabel, contractAddress, genesisHash);
    const request = input(journal);
    await expect(submitLocalIssuerProposalCall({
      ...request,
      readFinalizedLedger: async () => ({ ...identity, ledger: fixture().ledger }),
    })).rejects.toThrow(/Finalized issuer ledger read belongs to a different/u);
    expect(await journal.read("issuer", authorizationLabel)).toBeNull();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it("does not reserve when the submitting providers report another contract", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registryLabel, contractAddress, genesisHash);
    const request = input(journal);
    await expect(submitLocalIssuerProposalCall({
      ...request,
      readSubmissionProviderIdentity: async () => ({ contractAddress: `0x${"b".repeat(64)}`, genesisHash }),
    })).rejects.toThrow(/providers do not match/u);
    expect(await journal.read("issuer", authorizationLabel)).toBeNull();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it.each([
    ["registry", "registry:other", contractAddress],
    ["contract", registryLabel, `0x${"b".repeat(64)}`],
  ])("does not reserve when the journal is bound to another %s", async (_name, registry, address) => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registry, address, genesisHash);
    await expect(submitLocalIssuerProposalCall(input(journal)))
      .rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    expect(await journal.read("issuer", authorizationLabel)).toBeNull();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });
});
