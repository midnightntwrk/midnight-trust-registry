import { Buffer } from "node:buffer";
import type { Server } from "node:http";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import {
  sha256Hex,
  type RecognitionAuthorityAssertion,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createRecognitionAccreditationVpScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  recognitionAccreditationSubmissionCommitment,
  recognitionAuthorityAssertionDigest,
  RECOGNITION_VP_FIXTURE_ANCHOR,
  RECOGNITION_VP_FIXTURE_AUTHORITY_DID,
  RECOGNITION_VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";
import { afterEach, describe, expect, it } from "vitest";

import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import type { RecognitionAccreditationHttpPort } from "../recognition-accreditation-http.js";
import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";

const NOW = RECOGNITION_VP_FIXTURE_TIME_MS;
const authorityDid = RECOGNITION_VP_FIXTURE_AUTHORITY_DID;
const recognitionId = "recognition:http-accreditation:v1";

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address expected");
  return `http://127.0.0.1:${address.port.toString()}`;
}

const post = (url: string, body: unknown, authorized = true) => fetch(url, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    ...(authorized ? { "x-authority-did": authorityDid } : {}),
  },
  body: JSON.stringify(body),
});

describe("private recognition accreditation HTTP", () => {
  let server: Server | undefined;
  afterEach(async () => {
    if (server !== undefined) {
      await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
      server = undefined;
    }
  });

  it("fails closed without a trusted port and does not expose private CORS", async () => {
    server = createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "recognition-no-port" }).snapshot),
    });
    const base = await listen(server);
    const path = `${base}/v1/recognition-evidence/${recognitionId}/challenges`;
    const response = await post(path, {});
    expect(response.status).toBe(503);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    const preflight = await fetch(path, { method: "OPTIONS", headers: { origin: "https://untrusted.example" } });
    expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("verifies signed accreditation over HTTP with governed policy and one-use challenge", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recognition-http-accreditation");
    const anchor = {
      ...RECOGNITION_VP_FIXTURE_ANCHOR,
      targetRegistryId: harness.registryId,
      policyId: harness.policyId,
      policyVersion: `v${(harness.simulator.getLedger().governancePolicyVersion + 1n).toString()}`,
    };
    harness.governRecognitionAccreditorAnchor(anchor);
    const binding = {
      targetRegistryId: harness.registryId,
      recognitionId,
      authorityDid,
      recognizedRegistryId: anchor.recognizedRegistryId,
      scopeResourceType: anchor.scopeResourceType,
      scopeResourceId: anchor.scopeResourceId,
    };
    let policyCommitment = `0x${Buffer.from(harness.simulator.getLedger().governancePolicyCommitment).toString("hex")}`;
    let fixture: Awaited<ReturnType<typeof createRecognitionAccreditationVpScenarioFixture>> | undefined;
    const port: RecognitionAccreditationHttpPort = {
      challengeStore: new InMemoryApplicationChallengeStore(),
      authorizeRequest: async (_id, request) => {
        if (request.headers["x-authority-did"] !== authorityDid) throw new Error("forbidden");
      },
      resolveCurrentContext: async (id) => id !== recognitionId || fixture === undefined ? null : {
        binding,
        governancePolicy: harness.policyRecord,
        activePolicyCommitment: policyCommitment,
        resolver: fixture.input.resolver,
        statusSource: fixture.input.statusSource,
      },
    };
    // The server supplies the current policy/status dependencies; no such fields occur in the submitted body.
    fixture = await createRecognitionAccreditationVpScenarioFixture({ anchor });
    server = createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "recognition-http-source" }).snapshot),
      clock: () => new Date(NOW).toISOString(),
      recognitionAccreditation: port,
    });
    const base = await listen(server);
    const path = `${base}/v1/recognition-evidence/${recognitionId}`;
    expect((await post(`${path}/challenges`, {}, false)).status).toBe(403);
    policyCommitment = sha256Hex("stale-policy");
    expect((await post(`${path}/challenges`, {})).status).toBe(403);
    policyCommitment = `0x${Buffer.from(harness.simulator.getLedger().governancePolicyCommitment).toString("hex")}`;
    const issued = await post(`${path}/challenges`, {});
    expect(issued.status).toBe(201);
    const challenge = await issued.json() as { nonce: string; challengeHash: string };
    fixture = await createRecognitionAccreditationVpScenarioFixture({ anchor, nonce: challenge.nonce });
    const statement: RecognitionAuthorityAssertion = {
      version: "tr-recognition-authority-assertion-v1",
      ...binding,
      accreditationSubmissionCommitment: recognitionAccreditationSubmissionCommitment(fixture.input.submission),
      challengeHash: challenge.challengeHash,
      issuedAt: new Date(NOW).toISOString(),
      expiresAt: new Date(NOW + 5 * 60_000).toISOString(),
    };
    const methodId = `${authorityDid}#assertion-1`;
    const signed = {
      statement,
      proof: {
        verificationMethodId: methodId,
        algorithm: "jubjub-schnorr",
        signature: `0x${Buffer.from(encodeJubjubSignature(signJubjubDigestFromSeed(
          fixture.authorityAssertionSeed,
          recognitionAuthorityAssertionDigest(statement, methodId),
        ))).toString("hex")}`,
      },
    };
    const body = { nonce: challenge.nonce, signed, accreditation: fixture.input.submission };
    policyCommitment = sha256Hex("stale-policy");
    expect((await post(`${path}/submissions`, body)).status).toBe(403);
    policyCommitment = `0x${Buffer.from(harness.simulator.getLedger().governancePolicyCommitment).toString("hex")}`;
    const accepted = await post(`${path}/submissions`, body);
    expect(accepted.status).toBe(200);
    expect(accepted.headers.get("access-control-allow-origin")).toBeNull();
    expect(accepted.headers.get("cache-control")).toBe("no-store");
    const result = await accepted.json() as Record<string, unknown>;
    expect(result).toEqual({
      recognitionId,
      evidenceCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      expiresAt: new Date(NOW + 5 * 60_000).toISOString(),
    });
    expect(JSON.stringify(result)).not.toContain(authorityDid);
    expect((await post(`${path}/submissions`, body)).status).toBe(403);
  });
});
