import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
  signVerifierProposalEvidenceFromSeed,
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
import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");

const signPrepared = (maintainer: MaintainerScenarioFixture, prepared: PreparedGovernedVerifierProposal) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    bytes(prepared.registryId),
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
    const evidence = harness.createApplicationEvidence({
      applicationId: verifier.authorizationId,
      subjectDid: verifier.subjectDid,
      role: "verifier",
      scope: createVerifierAuthorizationScopeFixture(verifier),
    });
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
      async execute(authorizationId, submitted, signers, verifierSignature) {
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
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness,
        { label: "verifier-proposal-http", verifiers: [{ label: "candidate", fixture: verifier }] }) },
      governedVerifierProposals: port,
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
      const first = signPrepared(second, prepared);
      const other = signPrepared(third, prepared);
      const submit = (context: PreparedGovernedVerifierProposal, evidenceVerifierSignature: string,
        signers = [first, other]) => post("submit", { evidence, prepared: context, signers, evidenceVerifierSignature });
      const encoded = `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`;
      expect((await post("prepare", {
        evidence: { ...evidence, commitment: `0x${"00".repeat(32)}` },
      })).status).toBe(403);
      expect((await submit(prepared, encoded, [first])).status).toBe(403);
      const wrongSignature = signVerifierProposalEvidenceFromSeed(second.seed,
        bytes(prepared.registryId), bytes(prepared.evidenceVerifierKeyIdCommitment), bytes(prepared.actionPayloadHash));
      expect((await submit(prepared,
        `0x${Buffer.from(encodeJubjubSignature(wrongSignature)).toString("hex")}`)).status).toBe(403);
      expect((await submit(prepared, "0x00")).status).toBe(400);
      expect((await submit({ ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
        encoded)).status).toBe(409);
      const accepted = await submit(prepared, encoded);
      expect(accepted.status).toBe(202);
      const receipt = await accepted.json() as { eventHash: string };
      expect(receipt.eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(harness.simulator.getLedger().verifierAuthorizationCount).toBe(1n);
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
