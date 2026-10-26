import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signAuditorProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedAuditorProposalRejectedError,
  type GovernedAuditorProposalPort,
  type PreparedGovernedAuditorProposal,
} from "../governed-auditor-proposals.js";
import { createTrustRegistryApiServer } from "../server.js";
import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedGovernedAuditorProposal,
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

describe("Compact-backed auditor proposals over HTTP", () => {
  it("requires an injected port and rejects stale or wrongly signed evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("auditor-proposal-http");
    const second = createMaintainerScenarioFixture("auditor-http-second");
    const third = createMaintainerScenarioFixture("auditor-http-third");
    const auditor = createAuditorScenarioFixture("auditor-http-candidate");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = harness.createApplicationEvidence({
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope: createAuditorAuthorizationScopeFixture(auditor),
    });
    const source = { mode: "memory" as const, loadSnapshot: async () => publishSimulatorSnapshot(harness,
      { label: "auditor-proposal-http", auditors: [{ label: "candidate", fixture: auditor }] }) };
    const unavailable = createTrustRegistryApiServer({ source });
    try {
      await new Promise<void>((resolve) => unavailable.listen(0, "127.0.0.1", resolve));
      const address = unavailable.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      expect((await fetch(`http://127.0.0.1:${address.port}/v1/governed/auditor/app/proposal/prepare`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      })).status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => unavailable.close((error) => error ? reject(error) : resolve()));
    }
    const port: GovernedAuditorProposalPort = {
      async prepare(authorizationId, submitted) {
        if (authorizationId !== auditor.authorizationId) {
          throw new GovernedAuditorProposalRejectedError("unknown-authorization");
        }
        try {
          return harness.prepareAuditorProposalAction(auditor, submitted);
        } catch {
          throw new GovernedAuditorProposalRejectedError("invalid-evidence");
        }
      },
      async execute(authorizationId, submitted, signers, verifierSignature) {
        if (authorizationId !== auditor.authorizationId) {
          throw new GovernedAuditorProposalRejectedError("unknown-authorization");
        }
        try {
          const eventHash = harness.executeAuditorProposalWithSignatures(
            auditor, submitted, signers, verifierSignature,
          );
          return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
        } catch {
          throw new GovernedAuditorProposalRejectedError("invalid-signers");
        }
      },
      async resolve(authorizationId) {
        if (authorizationId !== auditor.authorizationId) {
          throw new GovernedAuditorProposalRejectedError("unknown-authorization");
        }
        return resolveCompactProposalObservation(async () => harness.simulator.getLedger(),
          harness.registryId, "auditor", authorizationId);
      },
    };
    const server = createTrustRegistryApiServer({ source, governedAuditorProposals: port });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/auditor/${auditor.authorizationId}/proposal`;
      const post = (action: "prepare" | "submit" | "resolve", body: unknown) => fetch(`${endpoint}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      expect(await (await post("resolve", { evidence })).json()).toEqual({ state: "not-observed" });
      expect((await post("prepare", { evidence: { ...evidence, rawCredential: "secret" } })).status).toBe(400);
      const preparedResponse = await post("prepare", { evidence });
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const prepared = await preparedResponse.json() as PreparedGovernedAuditorProposal;
      expect(prepared.evidenceHash).toBe(evidence.commitment);
      const signature = harness.signAuditorProposalEvidence(harness.prepareAuditorProposalAction(auditor, evidence));
      const encoded = `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`;
      const signers = [signPrepared(harness, second, prepared), signPrepared(harness, third, prepared)];
      const submit = (context: PreparedGovernedAuditorProposal, proof: string, votes = signers) =>
        post("submit", { evidence, prepared: context, signers: votes, evidenceVerifierSignature: proof });
      expect((await submit(prepared, encoded, [signers[0]!])).status).toBe(403);
      const wrong = signAuditorProposalEvidenceFromSeed(second.seed,
        bytes(prepared.registryId), bytes(prepared.networkIdCommitment), bytes(prepared.contractAddress),
        bytes(prepared.evidenceVerifierKeyIdCommitment), bytes(prepared.actionPayloadHash));
      expect((await submit(prepared,
        `0x${Buffer.from(encodeJubjubSignature(wrong)).toString("hex")}`)).status).toBe(403);
      expect((await submit(prepared, "0x00")).status).toBe(400);
      expect((await submit({ ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
        encoded)).status).toBe(409);
      const accepted = await submit(prepared, encoded);
      expect(accepted.status).toBe(202);
      const receipt = await accepted.json() as { eventHash: string };
      expect(receipt.eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(harness.simulator.getLedger().auditorAuthorizationCount).toBe(1n);
      expect((await submit(prepared, encoded)).status).toBe(409);
      expect(await (await post("resolve", { evidence })).json()).toEqual({
        state: "observed", eventHash: receipt.eventHash,
      });
      expect((await post("resolve", {
        evidence: { ...evidence, commitment: `0x${"00".repeat(32)}` },
      })).status).toBe(409);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
