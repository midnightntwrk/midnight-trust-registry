import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signMaintainerProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
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
import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";

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
    const evidence = harness.createApplicationEvidence({
      applicationId: candidate.maintainerId,
      subjectDid: candidate.subjectDid,
      role: "maintainer",
      scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
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
      async execute(maintainerId, submitted, signers, verifierSignature) {
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
    const server = createTrustRegistryApiServer({ source, governedMaintainerProposals: port });
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
      expect((await submit(prepared, encoded, [signers[0]!])).status).toBe(403);
      const wrong = signMaintainerProposalEvidenceFromSeed(second.seed,
        bytes(prepared.registryId), bytes(prepared.evidenceVerifierKeyIdCommitment), bytes(prepared.actionPayloadHash));
      expect((await submit(prepared,
        `0x${Buffer.from(encodeJubjubSignature(wrong)).toString("hex")}`)).status).toBe(403);
      expect((await submit(prepared, "0x00")).status).toBe(400);
      expect((await submit({ ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
        encoded)).status).toBe(409);
      const accepted = await submit(prepared, encoded);
      expect(accepted.status).toBe(202);
      const receipt = await accepted.json() as { eventHash: string };
      expect(receipt.eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(harness.simulator.getLedger().maintainerMembershipCount).toBe(4n);
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
