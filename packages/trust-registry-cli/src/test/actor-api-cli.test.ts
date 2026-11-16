import { afterEach, describe, expect, it, vi } from "vitest";
import {
  SignedPendingApplicationSchema,
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
} from "@midnight-ntwrk/trust-registry-domain/browser";

import { runCli } from "../cli.js";

const apiBase = "http://127.0.0.1:4400";
const session = {
  actorDid: `did:midnight:undeployed:${"ab".repeat(32)}`,
  actorKeyId: `did:midnight:undeployed:${"ab".repeat(32)}#auth-1`,
  purpose: "applicant-session",
  origin: apiBase,
  registryId: "registry:local:trusted",
  genesisHash: `0x${"11".repeat(32)}`,
  contractAddress: `0x${"22".repeat(32)}`,
  accessToken: `trsa_${"a".repeat(43)}`,
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
};
const applicationId = "application:maintainer:mine:v1";
const authorizationId = "auth:maintainer:mine:v1";
const scope = { version: "tr-scope-v1" as const, role: "maintainer" as const, registryId: session.registryId };
const governedResource = { type: "registry" as const, id: session.registryId };
const scopeCommitment = computeAuthorizationScopeCommitment(scope);
const request = SignedPendingApplicationSchema.parse({
  applicationId, authorizationId, scope, governedResource,
  intent: {
    version: "tr-mutation-intent-v1", registryId: session.registryId,
    actorDid: session.actorDid, actorKeyId: session.actorKeyId, actorRole: "applicant",
    action: "apply", target: "maintainer", targetId: applicationId, scopeCommitment,
    payloadCommitment: computePendingApplicationPayloadCommitment({ applicationId, authorizationId, scope, governedResource }),
    nonce: `0x${"33".repeat(32)}`, expectedWorkspaceCommitment: `0x${"44".repeat(32)}`,
    expectedEpochId: null, issuedAt: new Date(Date.now() - 30_000).toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  },
  signature: { keyId: session.actorKeyId, algorithm: "jubjub-schnorr", value: `0x${"aa".repeat(96)}` },
});
const record = {
  authorizationId,
  binding: { registryId: session.registryId, applicationId, subjectDid: session.actorDid,
    evidenceVerifierDid: session.actorDid, role: "maintainer", policyId: "policy:membership:v1",
    policyVersion: "v1", scope, scopeCommitment, governedResource },
  status: "pending", createdAt: new Date().toISOString(),
};

async function capture(command: string, input: unknown, base = apiBase): Promise<{
  status: number; stdout: string; stderr: string;
}> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const status = await runCli([command, "--api-base", base], {
    stdout: (value) => stdout.push(value),
    stderr: (value) => stderr.push(value),
    readStdin: async () => JSON.stringify(input),
  });
  return { status, stdout: stdout.join(""), stderr: stderr.join("") };
}

afterEach(() => vi.unstubAllGlobals());

describe("actor API CLI", () => {
  it("registers a signed application without printing or persisting the session", async () => {
    const fetchMock = vi.fn(async () => Response.json(record));
    vi.stubGlobal("fetch", fetchMock);
    const result = await capture("api-register", { session, request });
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(record);
    expect(result.stdout).not.toContain(session.accessToken);
    expect(fetchMock).toHaveBeenCalledWith(`${apiBase}/v1/pending-applications`, {
      method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
      headers: { "content-type": "application/json", authorization: `Bearer ${session.accessToken}` },
      body: JSON.stringify(request),
    });
  });

  it("reads the private pending list without printing the bearer", async () => {
    const entries = [{ applicationId: "application:issuer:mine:v1", authorizationId: "auth:issuer:mine:v1",
      role: "issuer", status: "pending", createdAt: new Date().toISOString() }];
    const fetchMock = vi.fn(async () => Response.json({ entries }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await capture("api-applications", { session });
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ status: "available", entries });
    expect(result.stdout).not.toContain(session.accessToken);
    expect(fetchMock).toHaveBeenCalledWith(`${apiBase}/v1/pending-applications`, {
      method: "GET", credentials: "omit", cache: "no-store", redirect: "error",
      headers: { authorization: `Bearer ${session.accessToken}` },
    });
  });

  it("keeps unavailable, invalid purpose, and cross-origin results distinct", async () => {
    const fetchMock = vi.fn(async () => Response.json({
      type: "https://midnight.network/problems/trust-registry-api/pending-application-list-unavailable",
      status: 503,
    }, { status: 503 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(JSON.parse((await capture("api-applications", { session })).stdout)).toEqual({ status: "unavailable" });
    expect((await capture("api-applications", { session: { ...session, purpose: "maintainer-session" } })).status)
      .toBe(1);
    expect((await capture("api-applications", { session }, "https://foreign.example")).status).toBe(1);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("requires a signed request for registration and does not echo a malformed session", async () => {
    const fetchMock = vi.fn(async () => Response.json({}));
    vi.stubGlobal("fetch", fetchMock);
    const noRequest = await capture("api-register", { session });
    expect(noRequest.status).toBe(1);
    expect(noRequest.stderr).toContain("signed request");
    const badSession = await capture("api-register", { session: { ...session, accessToken: "private-leak" } });
    expect(badSession.status).toBe(1);
    expect(badSession.stderr).not.toContain("private-leak");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not suggest retrying a signed request when the response is lost", async () => {
    const fetchMock = vi.fn(async () => { throw new Error("socket closed after acceptance"); });
    vi.stubGlobal("fetch", fetchMock);
    const result = await capture("api-register", { session, request });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("outcome is unknown");
    expect(result.stderr).toContain("Do not resubmit");
    expect(result.stderr).not.toContain(session.accessToken);
    expect(result.stderr).not.toContain("socket closed");
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
