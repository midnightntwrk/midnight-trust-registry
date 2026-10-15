import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { createMaintainerFixture } from "@midnight-ntwrk/trust-registry-contract/testing";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  bytes32Commitment,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  GovernedPolicyActionRejectedError,
  type GovernedPolicyActionPort,
  type PreparedGovernedPolicyAction,
} from "../governed-policy-actions.js";
import { createTrustRegistryApiServer } from "../server.js";

const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;
const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");
const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: Pick<MaintainerScenarioFixture, "keyId" | "seed">,
  prepared: PreparedGovernedPolicyAction,
) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  return {
    keyId: hex(maintainer.keyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: hex(encodeJubjubSignature(signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      bytes(prepared.registryId),
      harness.simulator.getLedger().deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"),
      bytes(prepared.policyCommitment),
      bytes(prepared.actionKind),
      bytes(prepared.actionPayloadHash),
      BigInt(prepared.actionSequence),
    ))),
  };
};

describe("Compact-backed policy revision over HTTP", () => {
  it("fails closed without a governed policy port", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("policy-http-unavailable");
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "unavailable" }) },
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener unavailable");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/policy/thresholds/prepare`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ thresholds: { default: "2", emergency: "2", archival: "2" } }),
      });
      expect(response.status).toBe(503);
      expect((await response.json()).type).toMatch(/governed-policy-unavailable$/u);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("uses old-policy quorum for revision and new-policy quorum for verifier registration", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("policy-http");
    const second = createMaintainerScenarioFixture("policy-http-second");
    const third = createMaintainerScenarioFixture("policy-http-third");
    const outsider = createMaintainerScenarioFixture("policy-http-outsider");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);
    const thresholds = { default: "3", emergency: "2", archival: "2" };
    const port: GovernedPolicyActionPort = {
      async prepareThresholds(value) {
        return harness.prepareThresholdPolicyRevisionAction(
          BigInt(value.default), BigInt(value.emergency), BigInt(value.archival),
        );
      },
      async executeThresholds(value, signers) {
        try {
          return { eventHash: hex(harness.executeThresholdPolicyRevisionWithSignatures(
            BigInt(value.default), BigInt(value.emergency), BigInt(value.archival), signers,
          )) };
        } catch {
          throw new GovernedPolicyActionRejectedError();
        }
      },
      async prepareEvidenceVerifier() {
        return harness.prepareEvidenceVerifierRegistrationAction();
      },
      async executeEvidenceVerifier(signers) {
        try {
          return { eventHash: hex(harness.executeEvidenceVerifierRegistrationWithSignatures(signers)) };
        } catch {
          throw new GovernedPolicyActionRejectedError();
        }
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "policy-http" }) },
      governedPolicyActions: port,
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener unavailable");
      const base = `http://127.0.0.1:${address.port}/v1/governed/policy`;
      const post = (path: string, body: unknown) => fetch(`${base}/${path}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      expect((await post("thresholds/prepare", {
        thresholds: { ...thresholds, default: "03" },
      })).status).toBe(400);

      const preparedResponse = await post("thresholds/prepare", { thresholds });
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const revision = await preparedResponse.json() as PreparedGovernedPolicyAction;
      const secondVote = signPrepared(harness, second, revision);
      const thirdVote = signPrepared(harness, third, revision);
      const submitRevision = (prepared: PreparedGovernedPolicyAction, signers: unknown[]) =>
        post("thresholds/submit", { thresholds, prepared, signers });
      const before = harness.simulator.getLedger().governanceActionCount;
      expect((await submitRevision(revision, [secondVote])).status).toBe(403);
      expect((await submitRevision(revision, [secondVote, secondVote])).status).toBe(403);
      expect((await submitRevision(revision, [secondVote, signPrepared(harness, outsider, revision)])).status).toBe(403);
      expect((await submitRevision(revision, [
        { ...secondVote, signature: "0x01" }, thirdVote,
      ])).status).toBe(400);
      expect((await submitRevision({ ...revision, policyCommitment: hex(new Uint8Array(32)) },
        [secondVote, thirdVote])).status).toBe(409);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before);

      const revised = await submitRevision(revision, [secondVote, thirdVote]);
      expect(revised.status).toBe(202);
      expect((await revised.json()).eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect((await submitRevision(revision, [secondVote, thirdVote])).status).toBe(409);
      expect(harness.simulator.getLedger().maintainerThreshold).toBe(3n);
      const issuer = createIssuerScenarioFixture("policy-http-issuer");
      expect(() => harness.proposeIssuer(issuer, [second, third])).toThrow();

      const registrationResponse = await post("evidence-verifier/prepare", {});
      expect(registrationResponse.status).toBe(200);
      const registration = await registrationResponse.json() as PreparedGovernedPolicyAction;
      const bootstrap = createMaintainerFixture("bootstrap", 17);
      bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
      const bootstrapVote = signPrepared(harness, bootstrap, registration);
      const secondRegistrationVote = signPrepared(harness, second, registration);
      const thirdRegistrationVote = signPrepared(harness, third, registration);
      const submitRegistration = (prepared: PreparedGovernedPolicyAction, signers: unknown[]) =>
        post("evidence-verifier/submit", { prepared, signers });
      expect((await submitRegistration(registration, [bootstrapVote, secondRegistrationVote])).status).toBe(403);
      expect((await submitRegistration(registration,
        [bootstrapVote, secondRegistrationVote, secondRegistrationVote])).status).toBe(403);
      expect((await submitRegistration(registration,
        [bootstrapVote, secondRegistrationVote, signPrepared(harness, outsider, registration)])).status).toBe(403);
      expect((await submitRegistration({ ...registration, actionSequence: revision.actionSequence },
        [bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).status).toBe(409);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);

      const registered = await submitRegistration(registration,
        [bootstrapVote, secondRegistrationVote, thirdRegistrationVote]);
      expect(registered.status).toBe(202);
      expect((await registered.json()).eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect((await submitRegistration(registration,
        [bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).status).toBe(409);
      harness.proposeIssuer(issuer, [second, third]);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 3n);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  }, 120_000);
});
