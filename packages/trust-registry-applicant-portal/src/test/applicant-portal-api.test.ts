import { describe, expect, it, vi } from "vitest";

import { TrustRegistryApplicantPortalClient } from "../api.js";

const auditorEntry = (effectiveUntil: string | undefined) => ({
  label: "auditor",
  authorization: {
    authorizationId: "auth:auditor:inspection:v1",
    role: "auditor",
    status: "active",
    resourceType: "request-profile",
    resourceId: "audit-scope",
    trustLevel: "approved",
    subjectDid: "did:midnight:testnet:auditor",
    proposedAt: "2020-01-01T00:00:00Z",
    activeFrom: "2020-01-02T00:00:00Z",
    effectiveUntil,
  },
});

const inspectionClient = (auditorResponse: Response) => new TrustRegistryApplicantPortalClient(
  "http://127.0.0.1:4400",
  (async (input: RequestInfo | URL): Promise<Response> => {
    const path = new URL(String(input)).pathname;
    if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local" });
    if (path === "/v1/authorizations/auditor") return auditorResponse;
    if (path === "/v1/authorizations/issuer") return Response.json({ entries: [
      { label: "issuer", authorization: { role: "issuer", status: "active", activeFrom: "2020-01-01T00:00:00Z" } },
      { label: "expired", authorization: { role: "issuer", status: "active", activeFrom: "2020-01-01T00:00:00Z", effectiveUntil: "2024-01-01T00:00:00Z" } },
    ] });
    if (path === "/v1/recognitions") return Response.json({ entries: [
      { label: "recognized-active", recognition: { status: "active", effectiveFrom: "2020-01-01T00:00:00Z" } },
      { label: "recognized-expired", recognition: { status: "active", effectiveFrom: "2020-01-01T00:00:00Z", effectiveUntil: "2024-01-01T00:00:00Z" } },
    ] });
    return Response.json({ entries: [] });
  }) as typeof fetch,
);

describe("public auditor inspection", () => {
  it("does not display expired auditor grants as active", async () => {
    const client = inspectionClient(Response.json({ entries: [
      auditorEntry("2024-01-01T00:00:00Z"),
      auditorEntry(undefined),
    ] }));
    const inspection = await client.loadPublicInspection();
    expect(inspection.activeAuditors).toHaveLength(1);
    expect(inspection.activeIssuers).toHaveLength(1);
    expect(inspection.activeRecognitions.map((entry) => entry.label)).toEqual(["recognized-active"]);
    expect(inspection.warnings).toBeUndefined();
  });

  it("keeps other lanes when the auditor endpoint is unavailable", async () => {
    const client = inspectionClient(Response.json({ title: "unavailable" }, { status: 503 }));
    const inspection = await client.loadPublicInspection();
    expect(inspection.summary.registryLabel).toBe("local");
    expect(inspection.activeIssuers).toHaveLength(1);
    expect(inspection.activeAuditors).toHaveLength(0);
    expect(inspection.warnings).toEqual(["Auditor records are temporarily unavailable."]);
  });

  it("fails soft for a malformed auditor list", async () => {
    for (const response of [
      Response.json(null),
      Response.json({ entries: null }),
      Response.json({ entries: [{ label: "broken", authorization: { role: "auditor", status: "active", activeFrom: "2020-01-01T00:00:00Z" } }] }),
    ]) {
      const inspection = await inspectionClient(response).loadPublicInspection();
      expect(inspection.activeIssuers).toHaveLength(1);
      expect(inspection.activeRecognitions).toHaveLength(1);
      expect(inspection.activeAuditors).toHaveLength(0);
      expect(inspection.warnings).toEqual(["Auditor records are temporarily unavailable."]);
    }
  });
});

describe("private application VP exchange", () => {
  it("recovers recognition by receipt using only a same-origin authenticated session", async () => {
    const fetchImpl = vi.fn(async () => Response.json({ state: "not-observed" })) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", fetchImpl);
    const receiptId = `0x${"11".repeat(32)}`;
    const evidenceCommitment = `0x${"22".repeat(32)}`;
    expect(await client.resolveRecognitionProposal("recognition:partner", receiptId, evidenceCommitment))
      .toEqual({ state: "not-observed" });
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://registry.example/v1/governed/recognition/recognition%3Apartner/proposal/resolve",
      { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ receiptId, evidenceCommitment }) },
    );
  });

  it("submits a signed pending auditor application without cross-origin credentials", async () => {
    const binding = { applicationId: "application:auditor:one", role: "auditor" };
    const request = { applicationId: binding.applicationId, scope: { role: "auditor" }, intent: { action: "apply" }, signature: { value: "signed" } };
    const fetchImpl = vi.fn(async () => Response.json({ binding, status: "pending" })) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", fetchImpl);
    expect(await client.registerPendingApplication(request)).toEqual({ binding, status: "pending" });
    expect(fetchImpl).toHaveBeenCalledWith("https://registry.example/v1/pending-applications", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
  });

  it("sends only the challenge nonce, hash, and VP, then returns redacted evidence", async () => {
    const nonce = `0x${"1".repeat(64)}`;
    const challengeHash = `0x${"2".repeat(64)}`;
    const evidence = { envelope: { applicationId: "application:issuer:one" }, commitment: `0x${"3".repeat(64)}` };
    const receipt = { receiptId: `0x${"4".repeat(64)}`, evidenceCommitment: evidence.commitment };
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init! });
      return Response.json(calls.length === 1
        ? { applicationId: "application:issuer:one", nonce, challengeHash, issuedAt: "2026-10-13T00:00:00Z",
          expiresAt: "2026-10-13T00:05:00Z", supersededPrevious: false }
        : { evidence, receipt });
    }) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("http://127.0.0.1:4400", fetchImpl);
    const challenge = await client.issueApplicationChallenge("application:issuer:one");
    const presentation = { privateClaim: "not-for-storage" };
    const result = await client.submitApplicationPresentation("application:issuer:one", challenge, presentation);

    expect(calls.map((call) => new URL(call.url).pathname)).toEqual([
      "/v1/application-evidence/application%3Aissuer%3Aone/challenges",
      "/v1/application-evidence/application%3Aissuer%3Aone/submissions",
    ]);
    expect(calls.map((call) => call.init.method)).toEqual(["POST", "POST"]);
    expect(calls[0]?.init.body).toBe("{}");
    expect(JSON.parse(String(calls[1]?.init.body))).toEqual({ nonce, challengeHash, presentation });
    expect(result).toEqual({ evidence, receipt });
  });

  it("loads the canonical pending binding through the private authenticated route", async () => {
    const binding = { applicationId: "application:auditor:one", role: "auditor", scope: { role: "auditor" } };
    const fetchImpl = vi.fn(async () => Response.json(binding)) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", fetchImpl);
    expect(await client.loadPendingApplicationBinding(binding.applicationId)).toEqual(binding);
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://registry.example/v1/application-evidence/application%3Aauditor%3Aone/binding",
      { method: "GET", credentials: "same-origin" },
    );
  });

  it("recovers accepted evidence with a read-only same-origin request", async () => {
    const accepted = {
      evidence: { envelope: { applicationId: "application:issuer:one" }, commitment: `0x${"3".repeat(64)}` },
      receipt: { receiptId: `0x${"4".repeat(64)}`, evidenceCommitment: `0x${"3".repeat(64)}` },
    };
    const fetchImpl = vi.fn(async () => Response.json(accepted)) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", fetchImpl);
    expect(await client.loadAcceptedApplicationEvidence("application:issuer:one")).toEqual(accepted);
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://registry.example/v1/application-evidence/application%3Aissuer%3Aone/receipt",
      { method: "GET", credentials: "same-origin" },
    );
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("does not expose a rejected server body's private presentation data", async () => {
    const fetchImpl = vi.fn(async () => Response.json({
      title: "private-presentation-payload", detail: "secret credential claims",
    }, { status: 403 })) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("http://127.0.0.1:4400", fetchImpl);
    await expect(client.issueApplicationChallenge("application:issuer:one"))
      .rejects.toThrow("application evidence request failed (403)");
    await expect(client.submitApplicationPresentation("application:issuer:one", {
      nonce: `0x${"1".repeat(64)}`, challengeHash: `0x${"2".repeat(64)}`,
    }, { secret: "private-presentation-payload" }))
      .rejects.not.toThrow(/private-presentation-payload|credential claims/u);
    await expect(client.issueApplicationChallenge(" ")).rejects.toThrow("A valid application ID is required.");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
