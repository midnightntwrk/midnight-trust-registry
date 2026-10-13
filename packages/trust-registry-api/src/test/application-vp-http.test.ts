import type { Server } from "node:http";

import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import {
  computeAuthorizationScopeCommitment,
  issuerGovernedResourceId,
  type ApplicationChallengeBinding,
} from "@midnight-ntwrk/trust-registry-domain";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { type ApplicationVpHttpPort } from "../application-vp-http.js";
import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";

const START = Date.parse("2026-10-13T00:00:00.000Z");
const scope = {
  version: "tr-scope-v1",
  role: "issuer",
  credentialFamilyId: "credential-family:company",
  schemaId: "schema:company",
  schemaVersion: "1.0.0",
  credentialDefinitionId: "credential-definition:company",
  statusMethod: "midnight-status-registry-v1",
} as const;
const binding: ApplicationChallengeBinding = {
  registryId: "registry:trusted:one",
  applicationId: "application:issuer:one",
  subjectDid: "did:midnight:issuer:one",
  evidenceVerifierDid: "did:midnight:verifier:one",
  role: "issuer",
  policyId: "policy:trusted:v1",
  policyVersion: "v1",
  scope,
  scopeCommitment: computeAuthorizationScopeCommitment(scope),
  governedResource: { type: "credentialFamily", id: issuerGovernedResourceId(scope, "credentialFamily") },
};
const verifier = {
  did: binding.evidenceVerifierDid,
  keyIds: [`${binding.evidenceVerifierDid}#key-1`],
  algorithms: ["jubjub-schnorr" as const],
};

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address expected");
  return `http://127.0.0.1:${address.port.toString()}`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

describe("application VP HTTP intake", () => {
  let server: Server | undefined;
  let nowMs = START;
  let currentBinding: ApplicationChallengeBinding = binding;
  let currentVerifiers = [verifier];
  let port: ApplicationVpHttpPort;
  let base = "";

  const path = `/v1/application-evidence/${binding.applicationId}`;
  const post = (suffix: string, body: unknown) => fetch(`${base}${path}/${suffix}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });

  async function start(configurePort = true) {
    server = createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "vp-http" }).snapshot),
      clock: () => new Date(nowMs).toISOString(),
      ...(configurePort ? { applicationVp: port } : {}),
    });
    base = await listen(server);
  }

  beforeEach(() => {
    nowMs = START;
    currentBinding = binding;
    currentVerifiers = [verifier];
    port = {
      challengeStore: new InMemoryApplicationChallengeStore(),
      authorizeRequest: vi.fn(async () => {}),
      resolvePendingApplication: vi.fn(async (id) => id === binding.applicationId
        ? { binding: currentBinding, authorizedVerifiers: currentVerifiers } : null),
      verifyPresentation: vi.fn(async (presentation: unknown) => {
        const proof = presentation as { nonce?: string; subjectDid?: string; scopeCommitment?: string; secret?: string };
        if (proof.secret !== "private-vp" || typeof proof.nonce !== "string") {
          throw new Error("private-vp leaked from verifier");
        }
        return {
          nonce: proof.nonce,
          subjectDid: proof.subjectDid ?? "",
          scopeCommitment: proof.scopeCommitment ?? "",
          presentationHash: `0x${"2".repeat(64)}`,
          claimsCommitment: `0x${"3".repeat(64)}`,
          verifiedAt: new Date(nowMs).toISOString(),
          expiresAt: new Date(nowMs + 60_000).toISOString(),
        };
      }),
      signEvidence: vi.fn(async () => ({
        keyId: `${binding.evidenceVerifierDid}#key-1`, algorithm: "jubjub-schnorr" as const, value: "fixture-signature",
      })),
      verifyEvidenceSignature: (_commitment, signature) => signature.value === "fixture-signature",
      persistRedactedEvidence: vi.fn(async (_id, evidence) => ({
        receiptId: `0x${"4".repeat(64)}`, evidenceCommitment: evidence.commitment,
        acceptedAt: new Date(nowMs).toISOString(),
      })),
    };
  });

  afterEach(async () => {
    if (server !== undefined) await close(server);
    server = undefined;
  });

  it("requires an injected trusted port and rejects caller-supplied binding on both routes", async () => {
    await start(false);
    const unavailable = await post("challenges", {});
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers.get("access-control-allow-origin")).toBeNull();
    expect((await post("submissions", { nonce: "x" })).status).toBe(503);
    await close(server!);
    server = undefined;
    await start();
    expect((await post("challenges", { binding })).status).toBe(400);
    const issued = await (await post("challenges", {})).json() as { nonce: string; challengeHash: string };
    expect((await post("submissions", { nonce: issued.nonce, challengeHash: issued.challengeHash,
      presentation: {}, binding })).status).toBe(400);
    expect((await post("submissions", { nonce: issued.nonce, challengeHash: issued.challengeHash,
      presentation: {}, authorizedVerifiers: [verifier] })).status).toBe(400);
    expect(port.verifyPresentation).not.toHaveBeenCalled();
  });

  it("authorizes before reading either body and redacts denial without issuing or verifying", async () => {
    const insert = vi.spyOn(port.challengeStore, "insert");
    const readLive = vi.spyOn(port.challengeStore, "readLive");
    port.authorizeRequest = vi.fn(async (applicationId, request) => {
      expect(applicationId).toBe(binding.applicationId);
      expect(request.readableFlowing).toBeNull();
      expect(request.listenerCount("data")).toBe(0);
      throw new Error("private-vp applicant token and raw claims");
    });
    await start();
    for (const suffix of ["challenges", "submissions"]) {
      const response = await fetch(`${base}${path}/${suffix}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: '{"presentation":',
      });
      expect(response.status).toBe(403);
      expect(response.headers.get("access-control-allow-origin")).toBeNull();
      const text = await response.text();
      expect(text).toContain("application VP forbidden");
      expect(text).not.toMatch(/private-vp|applicant token|raw claims|presentation/iu);
    }
    expect(port.authorizeRequest).toHaveBeenCalledTimes(2);
    expect(port.resolvePendingApplication).not.toHaveBeenCalled();
    expect(insert).not.toHaveBeenCalled();
    expect(readLive).not.toHaveBeenCalled();
    expect(port.verifyPresentation).not.toHaveBeenCalled();
    expect(port.signEvidence).not.toHaveBeenCalled();
    expect(port.persistRedactedEvidence).not.toHaveBeenCalled();
  });

  it("verifies a submitted VP, persists only signed redacted evidence, and refuses replay", async () => {
    await start();
    const challengeResponse = await post("challenges", {});
    expect(challengeResponse.status).toBe(201);
    expect(challengeResponse.headers.get("cache-control")).toBe("no-store");
    expect(challengeResponse.headers.get("access-control-allow-origin")).toBeNull();
    const issued = await challengeResponse.json() as { nonce: string; challengeHash: string };
    const presentation = {
      nonce: issued.nonce, subjectDid: binding.subjectDid,
      scopeCommitment: binding.scopeCommitment, secret: "private-vp",
    };
    const submitted = await post("submissions", { nonce: issued.nonce, challengeHash: issued.challengeHash, presentation });
    expect(submitted.status).toBe(202);
    expect(submitted.headers.get("cache-control")).toBe("no-store");
    expect(submitted.headers.get("access-control-allow-origin")).toBeNull();
    const responseText = await submitted.text();
    expect(responseText).not.toContain("private-vp");
    expect(responseText).not.toContain(issued.nonce);
    const result = JSON.parse(responseText) as { evidence: { commitment: string; envelope: { applicationId: string } }; receipt: { evidenceCommitment: string } };
    expect(result.evidence.envelope.applicationId).toBe(binding.applicationId);
    expect(result.receipt.evidenceCommitment).toBe(result.evidence.commitment);
    expect(port.authorizeRequest).toHaveBeenCalledTimes(2);
    expect(port.persistRedactedEvidence).toHaveBeenCalledOnce();
    expect(JSON.stringify(vi.mocked(port.persistRedactedEvidence).mock.calls)).not.toContain("private-vp");
    expect((await post("submissions", { nonce: issued.nonce, challengeHash: issued.challengeHash, presentation })).status).toBe(409);
  });

  it("does not advertise cross-origin access to private VP routes", async () => {
    await start();
    const preflight = await fetch(`${base}${path}/challenges`, {
      method: "OPTIONS",
      headers: { origin: "https://untrusted.example", "access-control-request-method": "POST" },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
    const publicRoute = await fetch(`${base}/health`);
    expect(publicRoute.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("rejects a changed trusted binding and expired challenge before VP work", async () => {
    await start();
    const first = await (await post("challenges", {})).json() as { nonce: string; challengeHash: string };
    currentBinding = { ...binding, policyVersion: "v2" };
    const presentation = { nonce: first.nonce, subjectDid: binding.subjectDid,
      scopeCommitment: binding.scopeCommitment, secret: "private-vp" };
    expect((await post("submissions", { nonce: first.nonce, challengeHash: first.challengeHash, presentation })).status).toBe(409);
    expect(port.verifyPresentation).not.toHaveBeenCalled();
    nowMs += 5 * 60_000;
    const second = await (await post("challenges", {})).json() as { nonce: string; challengeHash: string };
    nowMs += 5 * 60_000;
    expect((await post("submissions", { nonce: second.nonce, challengeHash: second.challengeHash,
      presentation: { ...presentation, nonce: second.nonce } })).status).toBe(409);
    expect(port.persistRedactedEvidence).not.toHaveBeenCalled();
  });

  it("refuses policy rotation during VP verification and redacts verifier errors", async () => {
    await start();
    const issued = await (await post("challenges", {})).json() as { nonce: string; challengeHash: string };
    const presentation = { nonce: issued.nonce, subjectDid: binding.subjectDid,
      scopeCommitment: binding.scopeCommitment, secret: "private-vp" };
    vi.mocked(port.verifyPresentation).mockImplementationOnce(async () => {
      throw new Error("private-vp and raw claims from verifier");
    });
    const rejected = await post("submissions", { nonce: issued.nonce, challengeHash: issued.challengeHash, presentation });
    expect(rejected.status).toBe(403);
    const errorText = await rejected.text();
    expect(errorText).not.toMatch(/private-vp|raw claims|verifier/iu);
    vi.mocked(port.verifyPresentation).mockImplementationOnce(async () => {
      currentVerifiers = [{ ...verifier, keyIds: [`${binding.evidenceVerifierDid}#key-2`] }];
      return {
        nonce: issued.nonce, subjectDid: binding.subjectDid, scopeCommitment: binding.scopeCommitment,
        presentationHash: `0x${"2".repeat(64)}`, claimsCommitment: `0x${"3".repeat(64)}`,
        verifiedAt: new Date(nowMs).toISOString(), expiresAt: new Date(nowMs + 60_000).toISOString(),
      };
    });
    const changed = await post("submissions", { nonce: issued.nonce, challengeHash: issued.challengeHash, presentation });
    expect(changed.status).toBe(409);
    expect(port.persistRedactedEvidence).not.toHaveBeenCalled();
  });
});
