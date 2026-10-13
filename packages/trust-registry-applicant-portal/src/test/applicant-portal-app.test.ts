// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { canUsePrivateEvidenceHost, createApplicantPortalApp, escapeHtml } from "../app.js";

describe("trust registry applicant portal app", () => {
  it("permits private evidence only on the same secure or loopback origin", () => {
    expect(canUsePrivateEvidenceHost("https://registry.example", new URL("https://registry.example/app"))).toBe(true);
    expect(canUsePrivateEvidenceHost("http://127.0.0.1:4400", new URL("http://127.0.0.1:4400/app"))).toBe(true);
    expect(canUsePrivateEvidenceHost("http://127.0.0.1:4400", new URL("http://127.0.0.1:4175/app"))).toBe(false);
    expect(canUsePrivateEvidenceHost("http://registry.example", new URL("http://registry.example/app"))).toBe(false);
    expect(canUsePrivateEvidenceHost("https://user:secret@registry.example", new URL("https://registry.example/app"))).toBe(false);
  });

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
        proposedAt: "2020-01-01T00:00:00Z", activeFrom: "2020-01-02T00:00:00Z",
      },
    };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      requested.push(`${url.pathname}${url.search}`);
      if (url.pathname === "/v1/registry/summary") {
        return Response.json({
          registryLabel: "local", currentEpochId: "epoch:1",
          issuerCounts: counts(), verifierCounts: counts(),
          recognitionCounts: counts(),
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
    expect(root.querySelector<HTMLButtonElement>("[data-auditor-binding-form] button")?.disabled).toBe(true);
    expect(root.querySelector<HTMLButtonElement>("[data-auditor-registration-form] button")?.disabled).toBe(true);
    const registrationForm = root.querySelector<HTMLFormElement>("[data-auditor-registration-form]")!;
    registrationForm.querySelector<HTMLTextAreaElement>("[name='signedApplication']")!.value = '{"applicationId":"application:auditor:one"}';
    registrationForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("authenticated same-origin"));
    expect(requested.some((path) => path === "/v1/pending-applications/auditor")).toBe(false);
    const privateForm = root.querySelector<HTMLFormElement>("[data-auditor-binding-form]")!;
    privateForm.querySelector<HTMLInputElement>("[name='applicationId']")!.value = "application:auditor:one";
    privateForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("authenticated same-origin"));
    expect(requested.some((path) => path.startsWith("/v1/application-evidence/"))).toBe(false);
    const target = root.querySelector<HTMLSelectElement>("[name='target']")!;
    const injectedOption = document.createElement("option");
    injectedOption.value = "auditor";
    injectedOption.textContent = "Auditor";
    target.add(injectedOption);
    target.value = "auditor";
    root.querySelector<HTMLInputElement>("[name='label']")!.value = "forged-auditor";
    root.querySelector<HTMLFormElement>("[data-submit-form]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    expect(root.textContent).toContain("does not support that application role");
    expect(fetchImpl.mock.calls.every(([, init]) => init?.method !== "POST")).toBe(true);
  });

  it("loads the canonical auditor request and submits a VP without retaining it in the page", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const applicationId = "application:auditor:one";
    const nonce = `0x${"1".repeat(64)}`;
    const challengeHash = `0x${"2".repeat(64)}`;
    const binding = {
      applicationId, subjectDid: "did:midnight:auditor:one", role: "auditor",
      policyId: "policy:auditor", policyVersion: "v1", scopeCommitment: `0x${"3".repeat(64)}`,
      scope: { role: "auditor", requestProfileId: "audit-profile:one", purpose: "compliance" },
      governedResource: { type: "requestProfile", id: "request:one" },
    };
    const calls: Array<{ path: string; init: RequestInit | undefined }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      calls.push({ path, init });
      if (path === "/v1/pending-applications/auditor") return Response.json({ binding, status: "pending" });
      if (path.endsWith("/binding")) return Response.json(binding);
      if (path.endsWith("/challenges")) return Response.json({ applicationId, nonce, challengeHash, expiresAt: "2026-10-13T00:05:00Z" });
      if (path.endsWith("/submissions")) return Response.json({
        evidence: { commitment: `0x${"4".repeat(64)}` },
        receipt: { receiptId: `0x${"5".repeat(64)}` },
      });
      if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local", currentEpochId: "epoch:1" });
      return Response.json({ entries: [] });
    });
    const storage = { getItem: vi.fn(() => null), setItem: vi.fn() } as unknown as Storage;
    createApplicantPortalApp(root, {
      initialUrl: new URL("https://registry.example/app?apiBase=https%3A%2F%2Fregistry.example"),
      storage, fetchImpl: fetchImpl as typeof fetch,
    });
    await vi.waitFor(() => expect(root.textContent).toContain("Pending auditor evidence"));
    const registrationForm = root.querySelector<HTMLFormElement>("[data-auditor-registration-form]")!;
    registrationForm.querySelector<HTMLTextAreaElement>("[name='signedApplication']")!.value = JSON.stringify({
      applicationId, scope: binding.scope, intent: { action: "apply" }, signature: { value: "signed-request-marker" },
    });
    registrationForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("registered. Present eligibility evidence next"));
    expect(root.innerHTML).not.toContain("signed-request-marker");
    expect(calls.find((call) => call.path === "/v1/pending-applications/auditor")?.init?.method).toBe("POST");
    const bindingForm = root.querySelector<HTMLFormElement>("[data-auditor-binding-form]")!;
    bindingForm.querySelector<HTMLInputElement>("[name='applicationId']")!.value = applicationId;
    bindingForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("audit-profile:one"));
    expect(root.textContent).toContain("did:midnight:auditor:one");
    root.querySelector<HTMLButtonElement>("[data-auditor-challenge]")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain(nonce));
    let vpForm = root.querySelector<HTMLFormElement>("[data-auditor-vp-form]")!;
    vpForm.querySelector<HTMLTextAreaElement>("[name='presentation']")!.value = '{"privateClaim":"still-editing"}';
    root.querySelector<HTMLButtonElement>("[data-refresh]")!.click();
    await vi.waitFor(() => expect(root.querySelector<HTMLTextAreaElement>("[data-auditor-vp-form] [name='presentation']")?.value)
      .toBe('{"privateClaim":"still-editing"}'));
    vpForm = root.querySelector<HTMLFormElement>("[data-auditor-vp-form]")!;
    vpForm.querySelector<HTMLTextAreaElement>("[name='presentation']")!.value = '{"privateClaim":"never-render-me"';
    vpForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("Presentation must be valid JSON."));
    expect(root.innerHTML).not.toContain("never-render-me");
    expect(calls.some((call) => call.path.endsWith("/submissions"))).toBe(false);
    root.querySelector<HTMLButtonElement>("[data-auditor-challenge]")!.click();
    await vi.waitFor(() => expect(root.querySelector("[data-auditor-vp-form]")).not.toBeNull());
    vpForm = root.querySelector<HTMLFormElement>("[data-auditor-vp-form]")!;
    vpForm.querySelector<HTMLTextAreaElement>("[name='presentation']")!.value = JSON.stringify({ privateClaim: "never-render-me" });
    vpForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("Auditor evidence accepted"));
    expect(root.innerHTML).not.toContain("never-render-me");
    expect(storage.setItem).not.toHaveBeenCalled();
    expect(calls.find((call) => call.path.endsWith("/submissions"))?.init?.body).toBe(
      JSON.stringify({ nonce, challengeHash, presentation: { privateClaim: "never-render-me" } }),
    );
    expect(root.querySelector("[data-auditor-vp-form]")).toBeNull();
  });

  it("rejects a non-auditor binding before issuing a challenge", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/binding")) return Response.json({
        applicationId: "application:auditor:one", role: "verifier", scope: { role: "verifier" },
        governedResource: { type: "requestProfile", id: "request:one" },
      });
      if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local" });
      return Response.json({ entries: [] });
    });
    createApplicantPortalApp(root, {
      initialUrl: new URL("https://registry.example/app?apiBase=https%3A%2F%2Fregistry.example"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch,
    });
    const form = root.querySelector<HTMLFormElement>("[data-auditor-binding-form]")!;
    form.querySelector<HTMLInputElement>("[name='applicationId']")!.value = "application:auditor:one";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("not a canonical auditor request"));
    expect(root.querySelector("[data-auditor-challenge]")).toBeNull();
    expect(fetchImpl.mock.calls.some(([input]) => String(input).endsWith("/challenges"))).toBe(false);
  });

  it("discards a pending binding response after the API host changes", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    let releaseBinding: ((response: Response) => void) | undefined;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/binding")) {
        return await new Promise<Response>((resolve) => { releaseBinding = resolve; });
      }
      if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local" });
      return Response.json({ entries: [] });
    });
    createApplicantPortalApp(root, {
      initialUrl: new URL("https://registry.example/app?apiBase=https%3A%2F%2Fregistry.example"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch,
    });
    const form = root.querySelector<HTMLFormElement>("[data-auditor-binding-form]")!;
    form.querySelector<HTMLInputElement>("[name='applicationId']")!.value = "application:auditor:one";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(releaseBinding).toBeDefined());
    const baseForm = root.querySelector<HTMLFormElement>("[data-api-base-form]")!;
    baseForm.querySelector<HTMLInputElement>("[name='apiBase']")!.value = "https://new-registry.example";
    baseForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    releaseBinding!(Response.json({
      applicationId: "application:auditor:one", role: "auditor", scope: { role: "auditor" },
      governedResource: { type: "requestProfile", id: "old-resource" },
    }));
    await vi.waitFor(() => expect(root.textContent).toContain("Private evidence is disabled"));
    expect(root.textContent).not.toContain("old-resource");
    expect(root.querySelector("[data-auditor-challenge]")).toBeNull();
  });
});
