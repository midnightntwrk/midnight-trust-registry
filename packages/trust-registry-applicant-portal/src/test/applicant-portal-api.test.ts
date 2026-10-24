import { describe, expect, it, vi } from "vitest";

import { TrustRegistryApplicantPortalClient } from "../api.js";

const auditorEntry = (effectiveUntil: string | undefined, authorizationId = "auth:auditor:inspection:v1") => ({
  label: "auditor",
  authorization: {
    authorizationId,
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

const issuerEntry = (authorizationId: string, effectiveUntil?: string) => ({
  label: authorizationId,
  authorization: {
    authorizationId, role: "issuer", status: "active", resourceType: "schema",
    resourceId: "tr:issuer-resource:v1:test", trustLevel: "approved",
    subjectDid: "did:midnight:undeployed:issuer", activeFrom: "2020-01-01T00:00:00Z",
    ...(effectiveUntil === undefined ? {} : { effectiveUntil }),
  },
});

const recognitionEntry = (recognitionId: string, effectiveUntil?: string) => ({
  label: recognitionId,
  recognition: {
    recognitionId, status: "active", recognizedAuthorityDid: "did:web:authority.example",
    trustLevel: "approved", scope: { resourceType: "schema", resourceId: "degree" },
    effectiveFrom: "2020-01-01T00:00:00Z",
    ...(effectiveUntil === undefined ? {} : { effectiveUntil }),
  },
});

const inspectionClient = (auditorResponse: Response) => new TrustRegistryApplicantPortalClient(
  "http://127.0.0.1:4400",
  (async (input: RequestInfo | URL): Promise<Response> => {
    const path = new URL(String(input)).pathname;
    if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local" });
    if (path === "/v1/authorizations/auditor") return auditorResponse;
    if (path === "/v1/authorizations/issuer") return Response.json({ entries: [
      issuerEntry("issuer"),
      issuerEntry("expired", "2024-01-01T00:00:00Z"),
    ] });
    if (path === "/v1/recognitions") return Response.json({ entries: [
      recognitionEntry("recognized-active"),
      recognitionEntry("recognized-expired", "2024-01-01T00:00:00Z"),
    ] });
    return Response.json({ entries: [] });
  }) as typeof fetch,
);

describe("public auditor inspection", () => {
  it("does not display expired auditor grants as active", async () => {
    const client = inspectionClient(Response.json({ entries: [
      auditorEntry("2024-01-01T00:00:00Z", "auth:auditor:expired:v1"),
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
    expect(inspection.unavailableLists).toEqual(["auditor"]);
    expect(inspection.warnings).toEqual(["Current auditor list is unavailable; no trust decision can be inferred."]);
  });

  it("fails soft for a malformed auditor list", async () => {
    for (const response of [
      Response.json(null),
      Response.json({ entries: null }),
      Response.json({ entries: [{ label: "broken", authorization: { role: "auditor", status: "active", activeFrom: "2020-01-01T00:00:00Z" } }] }),
      Response.json({ entries: [{ ...auditorEntry(undefined), authorization: {
        ...auditorEntry(undefined).authorization, role: "verifier",
      } }] }),
      Response.json({ entries: [auditorEntry(undefined), auditorEntry(undefined)] }),
    ]) {
      const inspection = await inspectionClient(response).loadPublicInspection();
      expect(inspection.activeIssuers).toHaveLength(1);
      expect(inspection.activeRecognitions).toHaveLength(1);
      expect(inspection.activeAuditors).toHaveLength(0);
      expect(inspection.unavailableLists).toEqual(["auditor"]);
      expect(inspection.warnings).toEqual(["Current auditor list is unavailable; no trust decision can be inferred."]);
    }
  });
});

describe("local list projection gate", () => {
  const unavailable = () => Response.json({
    type: "https://registry.example/problems/local-list-projection-unavailable",
    status: 503,
  }, { status: 503 });

  it("retains the summary while marking every gated list unavailable", async () => {
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", (async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/health") return Response.json({ status: "ok", sourceMode: "local-ledger", registryId: "registry:local" });
      return path === "/v1/registry/summary" ? Response.json({ registryLabel: "local", registryId: "registry:local" }) : unavailable();
    }) as typeof fetch);
    const inspection = await client.loadPublicInspection();
    expect(inspection.summary.registryLabel).toBe("local");
    expect(inspection.sourceMode).toBe("local-ledger");
    expect(inspection.unavailableLists).toEqual(["issuer", "verifier", "auditor", "recognition"]);
    expect(inspection.warnings).toHaveLength(4);
    expect(inspection.activeIssuers).toEqual([]);
    expect(inspection.activeRecognitions).toEqual([]);
  });

  it("rejects a local projection gate without confirmed local mode", async () => {
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", (async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/health") return Response.json({ status: "ok", sourceMode: "workspace" });
      return path === "/v1/registry/summary" ? Response.json({ registryLabel: "local" }) : unavailable();
    }) as typeof fetch);
    await expect(client.loadPublicInspection()).rejects.toThrow(/confirmed local-ledger/u);
  });

  it("rejects a local health and summary registry mismatch", async () => {
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", (async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/health") return Response.json({ status: "ok", sourceMode: "local-ledger", registryId: "registry:other" });
      return path === "/v1/registry/summary"
        ? Response.json({ registryLabel: "local", registryId: "registry:local" }) : unavailable();
    }) as typeof fetch);
    await expect(client.loadPublicInspection()).rejects.toThrow(/do not match/u);
  });

  it("does not downgrade unexpected issuer errors or malformed lists", async () => {
    for (const response of [
      Response.json({ status: 503, type: "other" }, { status: 503 }),
      Response.json({ entries: null }),
      Response.json({ entries: [issuerEntry("issuer"), issuerEntry("issuer")] }),
      Response.json({ role: "verifier", entries: [issuerEntry("issuer")] }),
      Response.json({ total: 2, entries: [issuerEntry("issuer")] }),
      Response.json({ entries: [{ ...issuerEntry("issuer"), authorization: {
        ...issuerEntry("issuer").authorization, activeFrom: "invalid",
      } }] }),
    ]) {
      const client = new TrustRegistryApplicantPortalClient("https://registry.example", (async (input) => {
        const path = new URL(String(input)).pathname;
        if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local" });
        if (path === "/v1/authorizations/issuer") return response;
        return Response.json({ entries: [] });
      }) as typeof fetch);
      await expect(client.loadPublicInspection()).rejects.toThrow();
    }
  });

  it("rejects malformed successful recognition lists instead of reporting zero", async () => {
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", (async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local" });
      if (path === "/v1/recognitions") return Response.json({ entries: [{
        ...recognitionEntry("recognized"), recognition: {
          ...recognitionEntry("recognized").recognition, effectiveFrom: "invalid",
        },
      }] });
      return Response.json({ entries: [] });
    }) as typeof fetch);
    await expect(client.loadPublicInspection()).rejects.toThrow(/Recognition list response was invalid/u);
  });
});

describe("private application VP exchange", () => {
  it("uses same-origin private routes for recognition challenge, accreditation, and receipt recovery", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const receipt = { receiptId: `0x${"11".repeat(32)}`, evidenceCommitment: `0x${"22".repeat(32)}` };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init! });
      if (String(input).endsWith("/challenges")) return Response.json({ recognitionId: "recognition:partner", nonce: "nonce" });
      if (String(input).endsWith("/submissions")) return Response.json({ recognitionId: "recognition:partner", receipt });
      return Response.json(receipt);
    }) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", fetchImpl);
    await client.issueRecognitionChallenge("recognition:partner");
    const submission = { nonce: "nonce", signed: { proof: "external" }, accreditation: { rawPresentationBody: "raw" } };
    await client.submitRecognitionAccreditation("recognition:partner", submission);
    expect(await client.loadAcceptedRecognitionAccreditation("recognition:partner")).toEqual(receipt);
    expect(calls.map(({ url }) => new URL(url).pathname)).toEqual([
      "/v1/recognition-evidence/recognition%3Apartner/challenges",
      "/v1/recognition-evidence/recognition%3Apartner/submissions",
      "/v1/recognition-evidence/recognition%3Apartner/accepted",
    ]);
    expect(calls.every(({ init }) => init.credentials === "same-origin" && init.cache === "no-store")).toBe(true);
    expect(JSON.parse(String(calls[1]?.init.body))).toEqual(submission);
  });

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
