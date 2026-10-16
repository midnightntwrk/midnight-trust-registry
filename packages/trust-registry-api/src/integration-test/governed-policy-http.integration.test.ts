import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";
import { CompactError } from "@midnight-ntwrk/compact-runtime";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { createMaintainerFixture } from "@midnight-ntwrk/trust-registry-contract/testing";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  bytes32Commitment,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  AtomicMaintainerRecoveryPrecheckError,
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
      bytes(prepared.networkIdCommitment),
      bytes(prepared.contractAddress),
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
    const fourth = createMaintainerScenarioFixture("policy-http-fourth");
    const outsider = createMaintainerScenarioFixture("policy-http-outsider");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.authorizeMaintainer(fourth);
    harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);
    const thresholds = { default: "3", emergency: "3", archival: "3" };
    const port: GovernedPolicyActionPort = {
      async prepareThresholds(value) {
        try {
          return harness.prepareThresholdPolicyRevisionAction(
            BigInt(value.default), BigInt(value.emergency), BigInt(value.archival),
          );
        } catch (error) {
          if (!(error instanceof CompactError)) throw error;
          throw new GovernedPolicyActionRejectedError();
        }
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
      expect((await post("thresholds/prepare", {
        thresholds: { default: "4", emergency: "2", archival: "2" },
      })).status).toBe(403);

      const preparedResponse = await post("thresholds/prepare", { thresholds });
      expect(preparedResponse.status).toBe(200);
      expect(preparedResponse.headers.get("cache-control")).toBe("no-store");
      const revision = await preparedResponse.json() as PreparedGovernedPolicyAction;
      expect(revision.networkIdCommitment).toBe(hex(harness.simulator.getLedger().deploymentNetworkIdCommitment));
      expect(revision.contractAddress).toBe(`0x${harness.simulator.contractAddress}`);
      const secondVote = signPrepared(second, revision);
      const thirdVote = signPrepared(third, revision);
      const submitRevision = (prepared: PreparedGovernedPolicyAction, signers: unknown[]) =>
        post("thresholds/submit", { thresholds, prepared, signers });
      const before = harness.simulator.getLedger().governanceActionCount;
      expect((await submitRevision(revision, [secondVote])).status).toBe(403);
      expect((await submitRevision(revision, [secondVote, secondVote])).status).toBe(403);
      expect((await submitRevision(revision, [secondVote, signPrepared(outsider, revision)])).status).toBe(403);
      expect((await submitRevision(revision, [secondVote, signPrepared(third, {
        ...revision, networkIdCommitment: hex(bytes32Commitment("wrong-network")),
      })])).status).toBe(403);
      expect((await submitRevision(revision, [secondVote, signPrepared(third, {
        ...revision, contractAddress: hex(bytes32Commitment("wrong-address")),
      })])).status).toBe(403);
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
      const bootstrapVote = signPrepared(bootstrap, registration);
      const secondRegistrationVote = signPrepared(second, registration);
      const thirdRegistrationVote = signPrepared(third, registration);
      const submitRegistration = (prepared: PreparedGovernedPolicyAction, signers: unknown[]) =>
        post("evidence-verifier/submit", { prepared, signers });
      expect((await submitRegistration(registration, [])).status).toBe(400);
      expect((await submitRegistration(registration, [signPrepared(outsider, registration)])).status).toBe(403);
      expect((await submitRegistration(registration,
        [bootstrapVote, secondRegistrationVote])).status).toBe(403);
      expect((await submitRegistration(registration,
        [bootstrapVote, bootstrapVote, thirdRegistrationVote])).status).toBe(403);
      expect((await submitRegistration({ ...registration, actionSequence: revision.actionSequence },
        [bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).status).toBe(409);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);

      const registered = await submitRegistration(registration,
        [bootstrapVote, secondRegistrationVote, thirdRegistrationVote]);
      expect(registered.status).toBe(202);
      expect((await registered.json()).eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect((await submitRegistration(registration,
        [bootstrapVote, secondRegistrationVote, thirdRegistrationVote])).status).toBe(409);
      expect(() => harness.proposeIssuer(issuer, [second])).toThrow();
      harness.proposeIssuer(issuer, [second, third]);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 3n);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  }, 120_000);

  it("atomically recovers a maintainer through old-quorum external signatures", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("policy-http-atomic-recovery");
    const second = createMaintainerScenarioFixture("policy-http-recovery-second");
    const target = createMaintainerScenarioFixture("policy-http-recovery-target");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(target);
    harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);
    const targetId = hex(target.maintainerIdCommitment);
    const thresholds = { default: "1", emergency: "1", archival: "1" };
    const port: GovernedPolicyActionPort = {
      async prepareThresholds() { throw new Error("Not configured for this test"); },
      async executeThresholds() { throw new Error("Not configured for this test"); },
      async prepareEvidenceVerifier() { throw new Error("Not configured for this test"); },
      async executeEvidenceVerifier() { throw new Error("Not configured for this test"); },
      async prepareMaintainerRecovery(maintainerId, value) {
        if (maintainerId !== targetId) throw new GovernedPolicyActionRejectedError();
        try {
          return harness.prepareAtomicMaintainerRecoveryAction(
            target, BigInt(value.default), BigInt(value.emergency), BigInt(value.archival),
          );
        } catch (error) {
          if (!(error instanceof CompactError || error instanceof AtomicMaintainerRecoveryPrecheckError)) {
            throw error;
          }
          throw new GovernedPolicyActionRejectedError();
        }
      },
      async executeMaintainerRecovery(maintainerId, value, signers) {
        if (maintainerId !== targetId) throw new GovernedPolicyActionRejectedError();
        try {
          return { eventHash: hex(harness.executeAtomicMaintainerRecoveryWithSignatures(
            target, BigInt(value.default), BigInt(value.emergency), BigInt(value.archival), signers,
          )) };
        } catch {
          throw new GovernedPolicyActionRejectedError();
        }
      },
    };
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "recovery" }) },
      governedPolicyActions: port,
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener unavailable");
      const endpoint = `http://127.0.0.1:${address.port}/v1/governed/policy/maintainer-recovery`;
      const post = (path: string, body: unknown) => fetch(`${endpoint}/${path}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      const request = { maintainerId: targetId, thresholds };
      const preparedResponse = await post("prepare", request);
      expect(preparedResponse.status).toBe(200);
      const prepared = await preparedResponse.json() as PreparedGovernedPolicyAction;
      expect(prepared.maintainerId).toBe(targetId);
      const bootstrap = createMaintainerFixture("bootstrap", 17);
      bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
      const bootstrapVote = signPrepared(bootstrap, prepared);
      const secondVote = signPrepared(second, prepared);
      const targetVote = signPrepared(target, prepared);
      const before = harness.simulator.getLedger().governanceActionCount;
      const submit = (context: PreparedGovernedPolicyAction, signers: unknown[]) =>
        post("submit", { ...request, prepared: context, signers });
      expect((await submit(prepared, [bootstrapVote])).status).toBe(403);
      expect((await submit(prepared, [bootstrapVote, targetVote])).status).toBe(403);
      expect((await submit({ ...prepared, actionSequence: "0" }, [bootstrapVote, secondVote])).status).toBe(409);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
      const recovered = await submit(prepared, [bootstrapVote, secondVote]);
      expect(recovered.status).toBe(202);
      const receipt = await recovered.json() as { eventHash: string };
      expect(receipt.eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
      expect(harness.simulator.getLedger().activeMaintainerCount).toBe(2n);
      expect(harness.simulator.getLedger().maintainerThreshold).toBe(1n);
      expect(harness.simulator.getMaintainerMembership(target.maintainerIdCommitment).status)
        .toBe(AuthorizationStatus.suspended);
      expect((await submit(prepared, [bootstrapVote, secondVote])).status).toBe(403);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  }, 120_000);
});
