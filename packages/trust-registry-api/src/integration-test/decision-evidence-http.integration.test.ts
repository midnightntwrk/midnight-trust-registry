import { afterEach, describe, expect, it } from "vitest";

import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import {
  DecisionEvidenceSchema,
  computeIssuerStatusPolicyBindingCommitment,
  issuerGovernedResourceId,
} from "@midnight-ntwrk/trust-registry-domain";
import { createIssuerScenarioFixture, LocalTrustRegistryIntegrationHarness } from "@midnight-ntwrk/trust-registry-integration";

import { createTrustRegistryApiServer } from "../server.js";

const A = `0x${"aa".repeat(32)}`;
const B = `0x${"bb".repeat(32)}`;
const C = `0x${"cc".repeat(32)}`;
const D = `0x${"dd".repeat(32)}`;
const servers: ReturnType<typeof createTrustRegistryApiServer>[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  })));
});

const fixture = (harness: LocalTrustRegistryIntegrationHarness) => {
  const issuer = createIssuerScenarioFixture("decision-query");
  const networkId = harness.registryDid.split(":")[2]!;
  const statusPolicyBinding = {
    version: "tr-issuer-status-policy-v1" as const,
    trustRegistryId: harness.registryId,
    issuerAuthorizationId: issuer.authorizationId,
    statusRegistryId: D,
    statusAuthorityVerificationMethod: `${issuer.subjectDid}#key-1`,
    statusPolicyId: "policy:status:v1",
    statusPolicyVersion: "v1",
    statusPolicyContentCommitment: C,
  };
  const policy = {
    format: "tr-policy-snapshot-v1" as const,
    registryId: harness.registryId,
    policyId: harness.policyId,
    policyVersion: "v1",
    effectiveFrom: "2026-05-20T00:00:00Z",
    effectiveUntil: null,
    contentCommitment: C,
    thresholds: [
      { family: "maintainer" as const, threshold: 1 },
      { family: "member" as const, threshold: 1 },
      { family: "emergency" as const, threshold: 1 },
      { family: "archival" as const, threshold: 1 },
    ],
  };
  return DecisionEvidenceSchema.parse({
    format: "tr-decision-evidence-v1",
    role: "issuer",
    registry: { registryId: harness.registryId, registryDid: harness.registryDid,
      networkId, contractAddress: A },
    anchorReferences: {
      registryEpoch: { networkId, contractAddress: A, transactionHash: B, blockHash: C },
      didState: { networkId, blockHash: D },
    },
    epoch: { epochId: "epoch:decision-query", registryId: harness.registryId, stateRoot: A,
      eventRoot: B, policyRoot: C, publicationPolicyCommitment: D,
      publicationSequence: "10", validFromSequence: "10", validUntilSequence: "20",
      validFrom: "2026-05-20T00:00:00Z", validUntil: "2026-05-21T00:00:00Z",
      quorum: { requiredSignatures: 1, signatures: [{ keyId: `${issuer.subjectDid}#key-1`,
        algorithm: "jubjub-schnorr", signature: `0x${"11".repeat(96)}` }] } },
    grant: { authorizationId: issuer.authorizationId, registryId: harness.registryId,
      subjectDid: issuer.subjectDid, role: "issuer", resourceType: "credential-family",
      resourceId: issuerGovernedResourceId(issuer.authorizationScope, "credentialFamily"),
      policyId: harness.policyId, trustLevel: "approved", status: "active",
      statusPolicyBindingCommitment: computeIssuerStatusPolicyBindingCommitment(statusPolicyBinding),
      lifecycleEventRoot: B, evidenceHash: D,
      proposedAt: "2026-05-20T00:00:00Z", authorizedAt: "2026-05-20T01:00:00Z",
      activeFrom: "2026-05-20T01:00:00Z" },
    scope: issuer.authorizationScope,
    statusPolicyBinding,
    didMethod: { did: issuer.subjectDid, methodId: `${issuer.subjectDid}#key-1`,
      methodType: "JsonWebKey", controller: issuer.subjectDid, relationship: "assertionMethod",
      publicKeyJwk: { kty: "EC", crv: "Jubjub", x: `${"A".repeat(42)}Q`, y: `${"B".repeat(42)}g` },
      stateVersion: "3", stateEvidence: { evidenceType: "ledger-observation",
        blockHash: D, transactionHash: B } },
    policy,
    inclusionProof: { proofType: "merkle-inclusion", root: A, leafHash: B, path: [C], leafIndex: "0" },
    governanceEvents: { grantTransition: A, quorumApproval: B, epochPublication: C, policySnapshot: D },
    decisionSequence: "11",
  });
};

describe("public decision-evidence query", () => {
  it("returns a structurally valid but explicitly client-unverified bundle for the exact grant", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("decision-query-api");
    const evidence = fixture(harness);
    let served: unknown = evidence;
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "decision-query" }) },
      readDecisionEvidence: async () => served,
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("API address unavailable");
    const base = `http://127.0.0.1:${address.port}/v1/decision-evidence`;
    const correct = await fetch(`${base}/issuer/${encodeURIComponent(evidence.grant.authorizationId)}`);
    expect(correct.status).toBe(200);
    expect(correct.headers.get("cache-control")).toBe("no-store");
    expect(await correct.json()).toEqual({ verification: "client-required", evidence });
    expect((await fetch(`${base}/issuer/another-grant`)).status).toBe(503);
    expect((await fetch(`${base}/verifier/${encodeURIComponent(evidence.grant.authorizationId)}`)).status).toBe(503);
    served = fixture(new LocalTrustRegistryIntegrationHarness("different-registry"));
    expect((await fetch(`${base}/issuer/${encodeURIComponent(evidence.grant.authorizationId)}`)).status).toBe(503);
  });

  it("fails closed when the source is absent, malformed, missing, or unavailable", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("decision-query-absent");
    const snapshot = () => publishSimulatorSnapshot(harness, { label: "decision-query" });
    const cases: {
      readDecisionEvidence?: () => Promise<unknown | null>;
      status: number;
    }[] = [
      { status: 503 },
      { readDecisionEvidence: async () => null, status: 404 },
      { readDecisionEvidence: async () => ({ format: "tr-decision-evidence-v1" }), status: 503 },
      { readDecisionEvidence: async () => { throw new Error("finality reader unavailable"); }, status: 503 },
    ];
    for (const { readDecisionEvidence, status } of cases) {
      const server = createTrustRegistryApiServer({ source: { mode: "memory", loadSnapshot: async () => snapshot() },
        ...(readDecisionEvidence === undefined ? {} : { readDecisionEvidence }) });
      servers.push(server);
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API address unavailable");
      const result = await fetch(`http://127.0.0.1:${address.port}/v1/decision-evidence/issuer/auth%3Aone`);
      expect(result.status).toBe(status);
    }
  });
});
