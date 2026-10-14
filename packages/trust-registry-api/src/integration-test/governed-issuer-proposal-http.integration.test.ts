import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signIssuerProposalEvidenceFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  issuerResourceTypeDetails,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedIssuerProposalRejectedError,
  type GovernedIssuerProposalPort,
  type PreparedGovernedIssuerProposal,
} from "../governed-issuer-proposals.js";
import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";
import { createTrustRegistryApiServer } from "../server.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");

const signPrepared = (maintainer: MaintainerScenarioFixture, prepared: PreparedGovernedIssuerProposal) => {
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

describe("Compact-backed issuer proposals over HTTP", () => {
  it("requires an injected proposal port", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("issuer-proposal-unavailable");
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "unavailable" }) },
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/issuer/app/proposal/prepare`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      expect(response.status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("binds signed application evidence, a registered verifier key, and 2-of-3 external maintainers", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("issuer-proposal-http");
    const second = createMaintainerScenarioFixture("issuer-proposal-second");
    const third = createMaintainerScenarioFixture("issuer-proposal-third");
    const issuer = createIssuerScenarioFixture("issuer-proposal-candidate");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: issuerResourceTypeDetails[issuer.resourceType].governedType, id: issuer.resourceId },
    });
    const port: GovernedIssuerProposalPort = {
      async prepare(authorizationId, submitted) {
        if (authorizationId !== issuer.authorizationId) {
          throw new GovernedIssuerProposalRejectedError("unknown-authorization");
        }
        try {
          return harness.prepareIssuerProposalAction(issuer, submitted);
        } catch {
          throw new GovernedIssuerProposalRejectedError("invalid-evidence");
        }
      },
      async execute(authorizationId, submitted, signers, verifierSignature) {
        if (authorizationId !== issuer.authorizationId) {
          throw new GovernedIssuerProposalRejectedError("unknown-authorization");
        }
        let eventHash: Uint8Array;
        try {
          eventHash = harness.executeIssuerProposalWithSignatures(issuer, submitted, signers, verifierSignature);
        } catch {
          throw new GovernedIssuerProposalRejectedError("invalid-signers");
        }
        return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
      },
      async resolve(authorizationId) {
        if (authorizationId !== issuer.authorizationId) {
          throw new GovernedIssuerProposalRejectedError("unknown-authorization");
        }
        return resolveCompactProposalObservation(async () => harness.simulator.getLedger(), "issuer", authorizationId);
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness,
        { label: "issuer-proposal-http", issuers: [{ label: "candidate", fixture: issuer }] }) },
      governedIssuerProposals: port,
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/issuer/${issuer.authorizationId}/proposal`;
      const post = (action: "prepare" | "submit" | "resolve", body: unknown) => fetch(`${endpoint}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      const notObserved = await post("resolve", { evidence });
      expect(notObserved.status).toBe(200);
      expect(notObserved.headers.get("cache-control")).toBe("no-store");
      expect(await notObserved.json()).toEqual({ state: "not-observed" });
      expect((await post("resolve", { evidence: { ...evidence, rawPresentation: "private" } })).status).toBe(400);
      expect((await post("prepare", {
        evidence: { ...evidence, rawPresentation: "private-presentation-payload" },
      })).status).toBe(400);
      expect((await post("prepare", {
        evidence: { ...evidence, envelope: { ...evidence.envelope, rawCredential: "private-vc" } },
      })).status).toBe(400);
      const preparedResponse = await post("prepare", { evidence });
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const prepared = await preparedResponse.json() as PreparedGovernedIssuerProposal;
      expect(prepared.evidenceHash).toBe(evidence.commitment);
      const verifierSignature = harness.signIssuerProposalEvidence(
        harness.prepareIssuerProposalAction(issuer, evidence),
      );
      const submit = (context: PreparedGovernedIssuerProposal, signers: ReturnType<typeof signPrepared>[]) =>
        post("submit", {
          evidence,
          prepared: context,
          signers,
          evidenceVerifierSignature: `0x${Buffer.from(encodeJubjubSignature(verifierSignature)).toString("hex")}`,
        });
      const first = signPrepared(second, prepared);
      const other = signPrepared(third, prepared);
      expect((await post("prepare", {
        evidence: { ...evidence, commitment: `0x${"00".repeat(32)}` },
      })).status).toBe(403);
      expect((await submit(prepared, [first])).status).toBe(403);
      const wrongVerifierSignature = signIssuerProposalEvidenceFromSeed(
        second.seed, bytes(prepared.registryId), bytes(prepared.evidenceVerifierKeyIdCommitment),
        bytes(prepared.actionPayloadHash),
      );
      expect((await post("submit", {
        evidence,
        prepared,
        signers: [first, other],
        evidenceVerifierSignature: `0x${Buffer.from(encodeJubjubSignature(wrongVerifierSignature)).toString("hex")}`,
      })).status).toBe(403);
      expect((await submit({ ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
        [first, other])).status).toBe(409);
      const accepted = await submit(prepared, [first, other]);
      expect(accepted.status).toBe(202);
      const receipt = await accepted.json() as { eventHash: string };
      expect(receipt.eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(1n);
      expect((await submit(prepared, [first, other])).status).toBe(409);
      const recovered = await post("resolve", { evidence });
      expect(recovered.status).toBe(200);
      expect(await recovered.json()).toEqual({ state: "observed", eventHash: receipt.eventHash });
      expect((await post("resolve", {
        evidence: { ...evidence, commitment: `0x${"00".repeat(32)}` },
      })).status).toBe(409);
      delete port.resolve;
      expect((await post("resolve", { evidence })).status).toBe(503);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
