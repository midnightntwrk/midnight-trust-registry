import { Buffer } from "node:buffer";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signMaintainerProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
  verifyMaintainerProposalEvidenceSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedMaintainerProposalRejectedError,
  type GovernedMaintainerProposalPort,
  type PreparedGovernedMaintainerProposal,
} from "../governed-maintainer-proposals.js";
import { createTrustRegistryApiServer } from "../server.js";
import { FileProposalSubmissionJournal } from "../proposal-submission-journal.js";
import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";
import { acceptedProposalAdmission } from "./fixtures/accepted-proposal-admission.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedGovernedMaintainerProposal,
) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    bytes(prepared.registryId),
    harness.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    bytes(prepared.policyCommitment),
    bytes(prepared.actionKind), bytes(prepared.actionPayloadHash), BigInt(prepared.actionSequence),
  );
  return {
    keyId: `0x${Buffer.from(maintainer.keyId).toString("hex")}`,
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`,
  };
};

describe("Compact-backed maintainer proposals over HTTP", () => {
  it("requires a port and rejects stale, insufficient, or wrongly signed evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("maintainer-proposal-http");
    const second = createMaintainerScenarioFixture("maintainer-http-second");
    const third = createMaintainerScenarioFixture("maintainer-http-third");
    const candidate = createMaintainerScenarioFixture("maintainer-http-candidate");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const scope = createMaintainerAuthorizationScopeFixture(harness.registryId);
    const evidence = harness.createApplicationEvidence({
      applicationId: candidate.maintainerId,
      subjectDid: candidate.subjectDid,
      role: "maintainer",
      scope,
    });
    const source = { mode: "memory" as const, loadSnapshot: async () => publishSimulatorSnapshot(harness,
      { label: "maintainer-proposal-http" }) };
    const unavailable = createTrustRegistryApiServer({ source });
    try {
      await new Promise<void>((resolve) => unavailable.listen(0, "127.0.0.1", resolve));
      const address = unavailable.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      expect((await fetch(`http://127.0.0.1:${address.port}/v1/governed/maintainer/app/proposal/prepare`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      })).status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => unavailable.close((error) => error ? reject(error) : resolve()));
    }
    let preflights = 0;
    let executions = 0;
    const port: GovernedMaintainerProposalPort = {
      async prepare(maintainerId, submitted) {
        if (maintainerId !== candidate.maintainerId) {
          throw new GovernedMaintainerProposalRejectedError("unknown-maintainer");
        }
        try {
          return harness.prepareMaintainerProposalAction(candidate, submitted);
        } catch {
          throw new GovernedMaintainerProposalRejectedError("invalid-evidence");
        }
      },
      async preflightSubmission(_maintainerId, _evidence, signers, signature, context) {
        preflights += 1;
        const ledger = harness.simulator.getLedger();
        if (BigInt(signers.length) < ledger.maintainerThreshold) {
          throw new GovernedMaintainerProposalRejectedError("invalid-signers");
        }
        if (!ledger.evidenceVerifierKeyRecords.member(context.evidenceVerifierAuthorizationId)
          || !verifyMaintainerProposalEvidenceSignature(
            ledger.evidenceVerifierKeyRecords.lookup(context.evidenceVerifierAuthorizationId).publicKey,
            context.registryId, context.networkIdCommitment, context.contractAddress,
            context.evidenceVerifierKeyIdCommitment, context.actionPayloadHash, signature,
          )) {
          throw new GovernedMaintainerProposalRejectedError("invalid-evidence");
        }
      },
      async execute(maintainerId, submitted, signers, verifierSignature) {
        executions += 1;
        if (maintainerId !== candidate.maintainerId) {
          throw new GovernedMaintainerProposalRejectedError("unknown-maintainer");
        }
        try {
          const eventHash = harness.executeMaintainerProposalWithSignatures(
            candidate, submitted, signers, verifierSignature,
          );
          return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
        } catch {
          throw new GovernedMaintainerProposalRejectedError("invalid-signers");
        }
      },
      async resolve(maintainerId) {
        if (maintainerId !== candidate.maintainerId) {
          throw new GovernedMaintainerProposalRejectedError("unknown-maintainer");
        }
        return resolveCompactProposalObservation(async () => harness.simulator.getLedger(),
          harness.registryId, "maintainer", maintainerId);
      },
    };
    const directory = await mkdtemp(join(tmpdir(), "tr-maintainer-preflight-"));
    const journal = new FileProposalSubmissionJournal(join(directory, "journal.json"));
    const server = createTrustRegistryApiServer({ source, governedMaintainerProposals: port,
      proposalSubmissionJournal: journal,
      proposalAdmission: acceptedProposalAdmission(candidate.maintainerId, scope, evidence) });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/maintainer/${candidate.maintainerId}/proposal`;
      const post = (action: "prepare" | "submit" | "resolve", body: unknown) => fetch(`${endpoint}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      expect(await (await post("resolve", { evidence })).json()).toEqual({ state: "not-observed" });
      expect((await post("prepare", { evidence: { ...evidence, rawCredential: "secret" } })).status).toBe(400);
      const preparedResponse = await post("prepare", { evidence });
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const prepared = await preparedResponse.json() as PreparedGovernedMaintainerProposal;
      expect(prepared.evidenceHash).toBe(evidence.commitment);
      const signature = harness.signMaintainerProposalEvidence(harness.prepareMaintainerProposalAction(candidate, evidence));
      const encoded = `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`;
      const signers = [signPrepared(harness, second, prepared), signPrepared(harness, third, prepared)];
      const submit = (context: PreparedGovernedMaintainerProposal, proof: string, votes = signers) =>
        post("submit", { evidence, prepared: context, signers: votes, evidenceVerifierSignature: proof });
      const insufficient = await submit(prepared, encoded, [signers[0]!]);
      expect(insufficient.status, await insufficient.text()).toBe(403);
      expect(preflights).toBe(1);
      expect(executions).toBe(0);
      expect(await journal.read("maintainer", candidate.maintainerId)).toBeNull();
      const wrong = signMaintainerProposalEvidenceFromSeed(second.seed,
        bytes(prepared.registryId), bytes(prepared.networkIdCommitment), bytes(prepared.contractAddress),
        bytes(prepared.evidenceVerifierKeyIdCommitment), bytes(prepared.actionPayloadHash));
      const wrongResponse = await submit(prepared,
        `0x${Buffer.from(encodeJubjubSignature(wrong)).toString("hex")}`);
      expect(wrongResponse.status).toBe(403);
      expect((await wrongResponse.json()).detail).toBe("invalid-evidence");
      expect(preflights).toBe(2);
      expect(executions).toBe(0);
      expect(await journal.read("maintainer", candidate.maintainerId)).toBeNull();
      expect((await submit(prepared, "0x00")).status).toBe(400);
      expect((await submit({ ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
        encoded)).status).toBe(409);
      const accepted = await submit(prepared, encoded);
      expect(accepted.status).toBe(202);
      const receipt = await accepted.json() as { eventHash: string };
      expect(receipt.eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      const recorded = await journal.read("maintainer", candidate.maintainerId);
      expect(recorded?.state).toBe("submitted");
      expect(recorded?.reservationContext).toEqual({ actionSequence: prepared.actionSequence,
        actionKind: prepared.actionKind, actionPayloadHash: prepared.actionPayloadHash });
      expect(harness.simulator.getLedger().maintainerMembershipCount).toBe(4n);
      expect((await submit(prepared, encoded)).status).toBe(409);
      expect(await (await post("resolve", { evidence })).json()).toEqual({
        state: "observed", eventHash: receipt.eventHash,
      });
      expect((await post("resolve", {
        evidence: { ...evidence, commitment: `0x${"00".repeat(32)}` },
      })).status).toBe(403);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await rm(directory, { recursive: true, force: true });
    }
  });
});
