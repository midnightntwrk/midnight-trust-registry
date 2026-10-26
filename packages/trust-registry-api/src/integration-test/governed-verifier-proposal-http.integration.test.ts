import { Buffer } from "node:buffer";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
  signVerifierProposalEvidenceFromSeed,
  verifyVerifierProposalEvidenceSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  createMaintainerScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedVerifierProposalRejectedError,
  type GovernedVerifierProposalPort,
  type PreparedGovernedVerifierProposal,
} from "../governed-verifier-proposals.js";
import { createTrustRegistryApiServer } from "../server.js";
import { FileProposalSubmissionJournal } from "../proposal-submission-journal.js";
import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";
import { acceptedProposalAdmission } from "./fixtures/accepted-proposal-admission.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedGovernedVerifierProposal,
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
    keyId: `0x${Buffer.from(maintainer.keyId).toString("hex")}`,
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`,
  };
};

describe("Compact-backed verifier proposals over HTTP", () => {
  it("requires an injected proposal port", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("verifier-proposal-unavailable");
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "unavailable" }) },
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/verifier/app/proposal/prepare`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      expect(response.status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("binds evidence and external signatures to a verifier proposal with replay protection", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("verifier-proposal-http");
    const second = createMaintainerScenarioFixture("verifier-http-second");
    const third = createMaintainerScenarioFixture("verifier-http-third");
    const verifier = createVerifierScenarioFixture("verifier-http-candidate");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const scope = createVerifierAuthorizationScopeFixture(verifier);
    const evidence = harness.createApplicationEvidence({
      applicationId: verifier.authorizationId,
      subjectDid: verifier.subjectDid,
      role: "verifier",
      scope,
    });
    let preflights = 0;
    let executions = 0;
    const port: GovernedVerifierProposalPort = {
      async prepare(authorizationId, submitted) {
        if (authorizationId !== verifier.authorizationId) {
          throw new GovernedVerifierProposalRejectedError("unknown-authorization");
        }
        try {
          return harness.prepareVerifierProposalAction(verifier, submitted);
        } catch {
          throw new GovernedVerifierProposalRejectedError("invalid-evidence");
        }
      },
      async preflightSubmission(_authorizationId, _evidence, signers, signature, context) {
        preflights += 1;
        const ledger = harness.simulator.getLedger();
        if (BigInt(signers.length) < ledger.maintainerThreshold) {
          throw new GovernedVerifierProposalRejectedError("invalid-signers");
        }
        if (!ledger.evidenceVerifierKeyRecords.member(context.evidenceVerifierAuthorizationId)
          || !verifyVerifierProposalEvidenceSignature(
            ledger.evidenceVerifierKeyRecords.lookup(context.evidenceVerifierAuthorizationId).publicKey,
            context.registryId, context.networkIdCommitment, context.contractAddress,
            context.evidenceVerifierKeyIdCommitment, context.actionPayloadHash, signature,
          )) {
          throw new GovernedVerifierProposalRejectedError("invalid-evidence");
        }
      },
      async execute(authorizationId, submitted, signers, verifierSignature) {
        executions += 1;
        if (authorizationId !== verifier.authorizationId) {
          throw new GovernedVerifierProposalRejectedError("unknown-authorization");
        }
        try {
          const eventHash = harness.executeVerifierProposalWithSignatures(
            verifier, submitted, signers, verifierSignature,
          );
          return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
        } catch {
          throw new GovernedVerifierProposalRejectedError("invalid-signers");
        }
      },
      async resolve(authorizationId) {
        if (authorizationId !== verifier.authorizationId) {
          throw new GovernedVerifierProposalRejectedError("unknown-authorization");
        }
        return resolveCompactProposalObservation(async () => harness.simulator.getLedger(),
          harness.registryId, "verifier", authorizationId);
      },
    };
    const directory = await mkdtemp(join(tmpdir(), "tr-verifier-preflight-"));
    const journal = new FileProposalSubmissionJournal(join(directory, "journal.json"));
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness,
        { label: "verifier-proposal-http", verifiers: [{ label: "candidate", fixture: verifier }] }) },
      governedVerifierProposals: port,
      proposalSubmissionJournal: journal,
      proposalAdmission: acceptedProposalAdmission(verifier.authorizationId, scope, evidence),
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/verifier/${verifier.authorizationId}/proposal`;
      const post = (action: "prepare" | "submit" | "resolve", body: unknown) => fetch(`${endpoint}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      expect(await (await post("resolve", { evidence })).json()).toEqual({ state: "not-observed" });
      expect((await post("prepare", {
        evidence: { ...evidence, rawPresentation: "private-presentation-payload" },
      })).status).toBe(400);
      const preparedResponse = await post("prepare", { evidence });
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const prepared = await preparedResponse.json() as PreparedGovernedVerifierProposal;
      expect(prepared.evidenceHash).toBe(evidence.commitment);
      const signature = harness.signVerifierProposalEvidence(harness.prepareVerifierProposalAction(verifier, evidence));
      const first = signPrepared(harness, second, prepared);
      const other = signPrepared(harness, third, prepared);
      const submit = (context: PreparedGovernedVerifierProposal, evidenceVerifierSignature: string,
        signers = [first, other]) => post("submit", { evidence, prepared: context, signers, evidenceVerifierSignature });
      const encoded = `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`;
      expect((await post("prepare", {
        evidence: { ...evidence, commitment: `0x${"00".repeat(32)}` },
      })).status).toBe(403);
      const insufficient = await submit(prepared, encoded, [first]);
      expect(insufficient.status, await insufficient.text()).toBe(403);
      expect(preflights).toBe(1);
      expect(executions).toBe(0);
      expect(await journal.read("verifier", verifier.authorizationId)).toBeNull();
      const wrongSignature = signVerifierProposalEvidenceFromSeed(second.seed,
        bytes(prepared.registryId), bytes(prepared.networkIdCommitment), bytes(prepared.contractAddress),
        bytes(prepared.evidenceVerifierKeyIdCommitment), bytes(prepared.actionPayloadHash));
      const wrong = await submit(prepared,
        `0x${Buffer.from(encodeJubjubSignature(wrongSignature)).toString("hex")}`);
      expect(wrong.status).toBe(403);
      expect((await wrong.json()).detail).toBe("invalid-evidence");
      expect(preflights).toBe(2);
      expect(executions).toBe(0);
      expect(await journal.read("verifier", verifier.authorizationId)).toBeNull();
      expect((await submit(prepared, "0x00")).status).toBe(400);
      expect((await submit({ ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
        encoded)).status).toBe(409);
      const accepted = await submit(prepared, encoded);
      expect(accepted.status).toBe(202);
      const receipt = await accepted.json() as { eventHash: string };
      expect(receipt.eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      const recorded = await journal.read("verifier", verifier.authorizationId);
      expect(recorded?.state).toBe("submitted");
      expect(recorded?.reservationContext).toEqual({ actionSequence: prepared.actionSequence,
        actionKind: prepared.actionKind, actionPayloadHash: prepared.actionPayloadHash });
      expect(harness.simulator.getLedger().verifierAuthorizationCount).toBe(1n);
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
