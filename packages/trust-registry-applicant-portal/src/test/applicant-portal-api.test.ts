import { describe, expect, it } from "vitest";

import { TrustRegistryApplicantPortalClient } from "../api.js";

const auditorEntry = (effectiveUntil: string | undefined) => ({
  label: "auditor",
  authorization: {
    authorizationId: "auth:auditor:inspection:v1",
    role: "auditor",
    status: "active",
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
    const inspection = await inspectionClient(Response.json({ entries: null })).loadPublicInspection();
    expect(inspection.activeIssuers).toHaveLength(1);
    expect(inspection.activeAuditors).toHaveLength(0);
    expect(inspection.warnings).toHaveLength(1);
  });
});
