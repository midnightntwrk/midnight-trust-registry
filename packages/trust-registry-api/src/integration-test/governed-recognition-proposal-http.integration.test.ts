import { Buffer } from "node:buffer";

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  EvidenceVerifierKeyStatus,
  MaintainerStatus,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
  signRecognitionProposalEvidenceFromSeed,
  verifyRecognitionProposalEvidenceSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import {
  bytes32Commitment,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  RECOGNITION_VP_FIXTURE_ANCHOR,
  RECOGNITION_VP_FIXTURE_AUTHORITY_DID,
  RECOGNITION_VP_FIXTURE_TIME_MS,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import { FileRecognitionAdmissionStore } from "../file-recognition-admission.js";
import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";
import {
  GovernedRecognitionProposalRejectedError,
  type GovernedRecognitionProposalPort,
  type PreparedGovernedRecognitionProposal,
} from "../governed-recognition-proposals.js";
import {
  recognitionAuthorityChallengeBindingHash,
  recognitionAuthorityChallengeIdentityHash,
} from "../recognition-authority-challenges.js";
import { createTrustRegistryApiServer } from "../server.js";
import { FileProposalSubmissionJournal } from "../proposal-submission-journal.js";

const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;
const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");
const now = RECOGNITION_VP_FIXTURE_TIME_MS + 60 * 60_000;
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

const sign = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedGovernedRecognitionProposal,
) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    bytes(prepared.registryId),
    harness.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    bytes(prepared.policyCommitment),
    bytes(prepared.actionKind),
    bytes(prepared.actionPayloadHash),
    BigInt(prepared.actionSequence),
  );
  return {
    keyId: hex(maintainer.keyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: hex(encodeJubjubSignature(signature)),
  };
};

describe("governed recognition proposal HTTP", () => {
  it("requires an injected Compact-backed port", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recognition-proposal-unavailable");
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "unavailable" }) },
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/recognition/test/proposal/prepare`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      expect(response.status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("requires a current admission and independent Compact quorum plus verifier signatures", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recognition-proposal-http");
    const second = createMaintainerScenarioFixture("recognition-http-second");
    const third = createMaintainerScenarioFixture("recognition-http-third");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const anchor = {
      ...RECOGNITION_VP_FIXTURE_ANCHOR,
      targetRegistryId: harness.registryId,
      policyId: harness.policyId,
      policyVersion: `v${(harness.simulator.getLedger().governancePolicyVersion + 1n).toString()}`,
    };
    harness.governRecognitionAccreditorAnchor(anchor, [second]);
    const base = createRecognitionScenarioFixture("recognition-proposal-http");
    const recognition = {
      ...base,
      recognizedAuthorityDid: RECOGNITION_VP_FIXTURE_AUTHORITY_DID,
      recognizedAuthorityDidCommitment: bytes32Commitment(RECOGNITION_VP_FIXTURE_AUTHORITY_DID),
      recognizedRegistryId: anchor.recognizedRegistryId,
      recognizedRegistryIdCommitment: bytes32Commitment(anchor.recognizedRegistryId),
      scopeResourceType: anchor.scopeResourceType,
      scopeResourceTypeCommitment: bytes32Commitment(anchor.scopeResourceType),
      scopeResourceId: anchor.scopeResourceId,
      scopeResourceIdCommitment: bytes32Commitment(anchor.scopeResourceId),
    };
    const binding = {
      targetRegistryId: harness.registryId,
      recognitionId: recognition.recognitionId,
      authorityDid: recognition.recognizedAuthorityDid,
      recognizedRegistryId: recognition.recognizedRegistryId,
      scopeResourceType: recognition.scopeResourceType,
      scopeResourceId: recognition.scopeResourceId,
    };
    const directory = await mkdtemp(join(tmpdir(), "tr-recognition-http-"));
    directories.push(directory);
    const governanceWorkspacePath = join(directory, "governance.json");
    const admissionStore = new FileRecognitionAdmissionStore(join(directory, "admission.json"), governanceWorkspacePath);
    const evidenceCommitment = sha256Hex("verified-combined-recognition-evidence");
    let finalizedLedger = harness.simulator.getLedger();
    const challengeHash = sha256Hex("recognition-proposal-challenge");
    await admissionStore.insert({
      challengeHash,
      bindingHash: recognitionAuthorityChallengeBindingHash(binding),
      applicationHash: recognitionAuthorityChallengeIdentityHash(binding),
      issuedAtMs: now - 60_000,
      expiresAtMs: now + 60_000,
    }, now - 60_000, () => now - 60_000);

    let recoveryAuthorized = true;
    const port: GovernedRecognitionProposalPort = {
      governanceWorkspacePath,
      admissionStore,
      async readBinding(recognitionId) {
        if (recognitionId !== recognition.recognitionId) throw new GovernedRecognitionProposalRejectedError("unknown-recognition");
        return binding;
      },
      async readCurrentGovernance() {
        return { governancePolicy: harness.policyRecord,
          activePolicyCommitment: hex(harness.simulator.getLedger().governancePolicyCommitment) };
      },
      async prepare(currentBinding, evidence) {
        if (currentBinding.recognitionId !== recognition.recognitionId
          || currentBinding.authorityDid !== recognition.recognizedAuthorityDid
          || currentBinding.recognizedRegistryId !== recognition.recognizedRegistryId
          || currentBinding.scopeResourceType !== recognition.scopeResourceType
          || currentBinding.scopeResourceId !== recognition.scopeResourceId) {
          throw new GovernedRecognitionProposalRejectedError("invalid-evidence");
        }
        return harness.prepareRecognitionProposalAction(recognition, bytes(evidence));
      },
      async preflightSubmission(_binding, _evidence, signers, verifierSignature, prepared) {
        const ledger = harness.simulator.getLedger();
        const verifierKey = ledger.evidenceVerifierKeyRecords.lookup(prepared.evidenceVerifierAuthorizationId);
        if (BigInt(signers.length) < ledger.maintainerThreshold
          || signers.some((signer) => {
            if (!ledger.maintainerKeyIds.member(signer.keyId)) return true;
            const registered = ledger.maintainerRecords.lookup(signer.keyId);
            return registered.status !== MaintainerStatus.active
              || registered.publicKey.x !== signer.publicKey.x
              || registered.publicKey.y !== signer.publicKey.y;
          })
          || verifierKey.status !== EvidenceVerifierKeyStatus.active
          || !Buffer.from(verifierKey.keyIdCommitment).equals(Buffer.from(prepared.evidenceVerifierKeyIdCommitment))
          || !verifyRecognitionProposalEvidenceSignature(
            verifierKey.publicKey,
            prepared.registryId,
            prepared.evidenceVerifierKeyIdCommitment,
            prepared.actionPayloadHash,
            verifierSignature,
          )) {
          throw new GovernedRecognitionProposalRejectedError("invalid-signers");
        }
      },
      async execute(currentBinding, evidence, signers, verifierSignature, prepared) {
        if (currentBinding.recognitionId !== recognition.recognitionId
          || currentBinding.authorityDid !== recognition.recognizedAuthorityDid
          || currentBinding.recognizedRegistryId !== recognition.recognizedRegistryId
          || currentBinding.scopeResourceType !== recognition.scopeResourceType
          || currentBinding.scopeResourceId !== recognition.scopeResourceId) {
          throw new GovernedRecognitionProposalRejectedError("invalid-evidence");
        }
        try {
          const eventHash = harness.executeRecognitionProposalWithSignatures(
            recognition, signers, verifierSignature, { ...prepared, evidenceHash: bytes(evidence) },
          );
          return { eventHash: hex(eventHash) };
        } catch {
          throw new GovernedRecognitionProposalRejectedError("invalid-signers");
        }
      },
      resolve: (recognitionId) => resolveCompactProposalObservation(
        async () => finalizedLedger, harness.registryId, "recognition", recognitionId,
      ),
    };
    const separateStore = new FileRecognitionAdmissionStore(join(directory, "other-admission.json"), governanceWorkspacePath);
    const journal = new FileProposalSubmissionJournal(join(directory, "proposal-journal.json"));
    expect(() => createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "mismatched" }) },
      governedRecognitionProposals: port,
      proposalSubmissionJournal: journal,
      recognitionAccreditation: {
        challengeStore: separateStore,
        admissionStore: separateStore,
        authorizeRequest: async () => {},
        resolveCurrentContext: async () => null,
      },
    })).toThrow(/same admission store/u);
    const noPreflightPort: GovernedRecognitionProposalPort = { ...port };
    delete noPreflightPort.preflightSubmission;
    expect(() => createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "no-preflight" }) },
      governedRecognitionProposals: noPreflightPort,
      proposalSubmissionJournal: journal,
      recognitionAccreditation: {
        challengeStore: admissionStore,
        admissionStore,
        authorizeRequest: async () => {},
        resolveCurrentContext: async () => null,
      },
    })).toThrow(/side-effect-free submission preflight/u);
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, {
        label: "recognition-proposal-http", recognitions: [{ label: "partner", fixture: recognition }],
      }) },
      governedRecognitionProposals: port,
      proposalSubmissionJournal: journal,
      recognitionAccreditation: {
        challengeStore: admissionStore,
        admissionStore,
        authorizeRequest: async () => {
          if (!recoveryAuthorized) throw new Error("private recovery denied");
        },
        resolveCurrentContext: async () => null,
      },
      clock: () => new Date(now + 1000).toISOString(),
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/recognition/${recognition.recognitionId}/proposal`;
      const post = (action: "prepare" | "submit", body: unknown) => fetch(`${endpoint}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      const resolve = (body: unknown) => fetch(`${endpoint}/resolve`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      recoveryAuthorized = false;
      expect((await resolve({ rawPresentation: "secret" })).status).toBe(403);
      recoveryAuthorized = true;
      const missing = { receiptId: sha256Hex("not-admitted"), evidenceCommitment };
      expect((await post("prepare", missing)).status).toBe(403);
      expect((await resolve(missing)).status).toBe(403);
      const admitted = await admissionStore.accept({
        targetRegistryId: binding.targetRegistryId,
        recognitionId: binding.recognitionId,
        challengeHash,
        bindingHash: recognitionAuthorityChallengeBindingHash(binding),
        policyCommitment: hex(harness.simulator.getLedger().governancePolicyCommitment),
        anchorCommitment: harness.resolveCurrentRecognitionAccreditorAnchor({
          recognizedRegistryId: binding.recognizedRegistryId,
          scopeResourceType: binding.scopeResourceType,
          scopeResourceId: binding.scopeResourceId,
          evaluatedAtMs: now,
        }).commitment,
        evidenceCommitment,
        expiresAtMs: now + 30_000,
        nowMs: now,
        assertCurrentGovernance: async () => {},
      });
      if (admitted === null) throw new Error("Test admission failed");
      const request = { receiptId: admitted.receiptId, evidenceCommitment };
      expect((await resolve({ ...request, receiptId: sha256Hex("wrong-receipt") })).status).toBe(403);
      expect((await resolve({ ...request, evidenceCommitment: sha256Hex("wrong-evidence") })).status).toBe(403);
      expect(await (await resolve(request)).json()).toEqual({ state: "not-observed" });
      expect((await post("prepare", { ...request, rawPresentation: "secret" })).status).toBe(400);
      expect((await post("prepare", { ...request, evidenceCommitment: sha256Hex("other") })).status).toBe(403);
      const preparedResponse = await post("prepare", request);
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const prepared = await preparedResponse.json() as PreparedGovernedRecognitionProposal;
      expect(prepared.evidenceHash).toBe(evidenceCommitment);
      const verifierSignature = harness.signRecognitionProposalEvidence(
        harness.prepareRecognitionProposalAction(recognition, bytes(evidenceCommitment)),
      );
      const submit = (signed: PreparedGovernedRecognitionProposal, signers: ReturnType<typeof sign>[],
        signature = verifierSignature) => post("submit", {
          ...request, prepared: signed, signers,
          evidenceVerifierSignature: hex(encodeJubjubSignature(signature)),
        });
      const first = sign(harness, second, prepared);
      const other = sign(harness, third, prepared);
      const outsider = sign(harness, createMaintainerScenarioFixture("recognition-outsider"), prepared);
      const insufficient = await submit(prepared, [first]);
      expect(insufficient.status, JSON.stringify(await insufficient.json())).toBe(403);
      expect((await submit(prepared, [first, outsider])).status).toBe(403);
      const wrongVerifier = signRecognitionProposalEvidenceFromSeed(
        second.seed, bytes(prepared.registryId), bytes(prepared.evidenceVerifierKeyIdCommitment),
        bytes(prepared.actionPayloadHash),
      );
      expect((await submit(prepared, [first, other], wrongVerifier)).status).toBe(403);
      expect((await submit({ ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
        [first, other])).status).toBe(409);
      expect(await journal.read("recognition", recognition.recognitionId)).toBeNull();
      const accepted = await submit(prepared, [first, other]);
      expect(accepted.status).toBe(202);
      expect((await accepted.json() as { eventHash: string }).eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(await journal.read("recognition", recognition.recognitionId)).toMatchObject({ state: "submitted", evidenceCommitment });
      expect(harness.simulator.getLedger().recognitionCount).toBe(1n);
      expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(0n);
      expect((await submit(prepared, [first, other])).status).toBe(409);
      expect(await (await resolve(request)).json()).toEqual({ state: "not-observed" });
      expect(await journal.read("recognition", recognition.recognitionId)).toMatchObject({ state: "submitted" });
      finalizedLedger = harness.simulator.getLedger();
      const recovered = await resolve(request);
      expect(recovered.status).toBe(200);
      expect(recovered.headers.get("cache-control")).toBe("no-store");
      expect(await recovered.json()).toEqual({ state: "observed", eventHash: hex(
        finalizedLedger.recognitionProposalEvidenceRecords.lookup(recognition.recognitionIdCommitment)
          .proposalGovernanceEventHash,
      ) });
      expect(await journal.read("recognition", recognition.recognitionId)).toMatchObject({ state: "observed" });
      port.resolve = async () => ({ eventHash: sha256Hex("unrelated-event"), evidenceCommitment: sha256Hex("unrelated-evidence") });
      expect((await resolve(request)).status).toBe(409);
      expect(await journal.read("recognition", recognition.recognitionId)).toMatchObject({ state: "observed" });
      port.resolve = async () => { throw new Error("finality source unavailable"); };
      expect((await resolve(request)).status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
