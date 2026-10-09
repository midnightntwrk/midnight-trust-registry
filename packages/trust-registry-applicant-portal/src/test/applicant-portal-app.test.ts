// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { createApplicantPortalApp, escapeHtml } from "../app.js";

describe("trust registry applicant portal app", () => {
  it("escapes dynamic content before rendering it into innerHTML", () => {
    expect(escapeHtml(`<degree>&"'`)).toBe(
      "&lt;degree&gt;&amp;&quot;&#39;",
    );
  });

  it("shows only active auditor grants without offering an unsigned auditor submission", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const requested: string[] = [];
    const counts = () => ({ proposed: 0, authorized: 0, active: 0, suspended: 0, revoked: 0, superseded: 0, archived: 0 });
    const auditorGrant = {
      label: "identity-audit",
      authorization: {
        authorizationId: "auth:auditor:identity-audit:v1",
        role: "auditor", status: "active", resourceType: "request-profile",
        resourceId: "tr:request-resource:v1:auditor-scope", trustLevel: "approved",
        subjectDid: "did:midnight:testnet:auditor",
      },
    };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      requested.push(`${url.pathname}${url.search}`);
      if (url.pathname === "/v1/registry/summary") {
        return Response.json({
          registryLabel: "local", currentEpochId: "epoch:1",
          issuerCounts: counts(), verifierCounts: counts(),
          auditorCounts: { ...counts(), active: 1 }, recognitionCounts: counts(),
        });
      }
      return Response.json({ entries: url.pathname === "/v1/authorizations/auditor" ? [
        auditorGrant,
        { ...auditorGrant, label: "wrong-role", authorization: { ...auditorGrant.authorization, role: "verifier" } },
        { ...auditorGrant, label: "archived-auditor", authorization: { ...auditorGrant.authorization, status: "archived" } },
      ] : [] });
    });
    createApplicantPortalApp(root, {
      initialUrl: new URL("http://127.0.0.1:4175/?apiBase=http://127.0.0.1:4400"),
      storage: window.localStorage,
      fetchImpl: fetchImpl as typeof fetch,
    });

    await vi.waitFor(() => expect(root.textContent).toContain("identity-audit"));
    expect(root.textContent).toContain("Active auditors");
    expect(root.textContent).toContain("did:midnight:testnet:auditor");
    expect(root.textContent).not.toContain("wrong-role");
    expect(root.textContent).not.toContain("archived-auditor");
    expect(requested).toContain("/v1/authorizations/auditor?status=active");
    expect(root.querySelector("option[value='auditor']")).toBeNull();
    expect(fetchImpl.mock.calls.every(([, init]) => init?.method !== "POST")).toBe(true);
  });
});
