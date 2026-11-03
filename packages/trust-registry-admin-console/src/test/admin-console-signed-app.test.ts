// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { createAdminConsoleApp } from "../app.js";

const did = `did:midnight:undeployed:${"2".repeat(64)}`;
const hash = `0x${"a".repeat(64)}`;
const context = {
  registryId: "registry:test:trusted",
  expectedEpochId: "epoch:registry:test:trusted:seq-1",
  expectedWorkspaceCommitment: hash,
};
const counts = { proposed: 0, authorized: 0, active: 0, suspended: 0, revoked: 0, superseded: 0, archived: 0 };
const summary = {
  registryLabel: "local", currentEpochId: context.expectedEpochId,
  issuerCounts: counts, verifierCounts: counts, auditorCounts: counts, recognitionCounts: counts,
};
const envelope = {
  intent: {
    version: "tr-mutation-intent-v1", registryId: context.registryId,
    actorDid: did, actorKeyId: `${did}#assertion-1`, actorRole: "maintainer",
    action: "approve", target: "issuer", targetId: "auth:issuer:degree:v1",
    scopeCommitment: hash, payloadCommitment: hash, nonce: hash,
    expectedWorkspaceCommitment: context.expectedWorkspaceCommitment,
    expectedEpochId: context.expectedEpochId,
    issuedAt: "2026-10-10T00:00:00.000Z", expiresAt: "2026-10-10T00:05:00.000Z",
  },
  signature: { keyId: `${did}#assertion-1`, algorithm: "jubjub-schnorr", value: `0x${"b".repeat(192)}` },
  operation: { operation: "approve", target: "issuer", id: "auth:issuer:degree:v1" },
};

describe("admin signed browser journey", () => {
  it("discards a signing context returned after board refresh", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    let releaseContext: (() => void) | undefined;
    const pendingContext = new Promise<void>((resolve) => { releaseContext = resolve; });
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path === "/health") return Response.json({ status: "ok", sourceMode: "workspace", registryId: context.registryId });
      if (path === "/v1/registry/summary") return Response.json(summary);
      if (path === "/v1/registry/mutation-context") {
        await pendingContext;
        return Response.json(context);
      }
      return Response.json({ entries: [] });
    });
    createAdminConsoleApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch, confirm: () => true,
    });
    await vi.waitFor(() => expect(root.querySelector("[data-signed-context]")).not.toBeNull());
    root.querySelector<HTMLButtonElement>("[data-signed-context]")!.click();
    await vi.waitFor(() => expect(fetchImpl.mock.calls.some(([input]) =>
      new URL(String(input)).pathname === "/v1/registry/mutation-context")).toBe(true));
    root.querySelector<HTMLButtonElement>("[data-refresh]")!.click();
    releaseContext?.();
    await vi.waitFor(() => expect(root.querySelector("[data-signed-context]")).not.toBeNull());
    expect(root.textContent).not.toContain(context.expectedWorkspaceCommitment);
    expect(root.querySelector<HTMLButtonElement>("[data-signed-submit] button")?.disabled).toBe(true);
  });
  it("confirms and forwards an external maintainer signature then clears its context", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const calls: Array<{ path: string; init: RequestInit | undefined }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      calls.push({ path, init });
      if (path === "/health") return Response.json({ status: "ok", sourceMode: "workspace", registryId: context.registryId });
      if (path === "/v1/registry/mutation-context") return Response.json(context);
      if (path === "/v1/mutations") return Response.json({ recordKind: "authorization", operation: envelope.operation });
      if (path === "/v1/registry/summary") return Response.json(summary);
      return Response.json({ entries: [] });
    });
    const confirm = vi.fn(() => true);
    createAdminConsoleApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch, confirm,
    });
    await vi.waitFor(() => expect(root.textContent).toContain("Submit an external maintainer intent"));
    root.querySelector<HTMLButtonElement>("[data-signed-context]")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain(context.expectedWorkspaceCommitment));
    expect(calls.find((call) => call.path === "/v1/registry/mutation-context")?.init).toEqual({ cache: "no-store" });
    const form = root.querySelector<HTMLFormElement>("[data-signed-submit]")!;
    form.querySelector<HTMLTextAreaElement>("[name='signedEnvelope']")!.value = JSON.stringify(envelope);
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(confirm).toHaveBeenCalledWith(
      "Submit signed approve for auth:issuer:degree:v1?",
    ));
    await vi.waitFor(() => expect(root.textContent).toContain("Signed approve accepted"));
    expect(calls.find((call) => call.path === "/v1/mutations")?.init?.body).toBe(JSON.stringify(envelope));
    expect(root.innerHTML).not.toContain(envelope.signature.value);
    expect(root.querySelector<HTMLTextAreaElement>("[name='signedEnvelope']")?.value).toBe("");
    expect(root.querySelector<HTMLButtonElement>("[data-signed-submit] button")?.disabled).toBe(true);
  });

  it("does not post a stale or applicant-role envelope from the admin panel", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path === "/health") return Response.json({ status: "ok", sourceMode: "workspace", registryId: context.registryId });
      if (path === "/v1/registry/mutation-context") return Response.json(context);
      if (path === "/v1/registry/summary") return Response.json(summary);
      return Response.json({ entries: [] });
    });
    createAdminConsoleApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch, confirm: () => true,
    });
    await vi.waitFor(() => expect(root.querySelector("[data-signed-context]")).not.toBeNull());
    root.querySelector<HTMLButtonElement>("[data-signed-context]")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain(context.expectedWorkspaceCommitment));
    const form = root.querySelector<HTMLFormElement>("[data-signed-submit]")!;
    form.querySelector<HTMLTextAreaElement>("[name='signedEnvelope']")!.value = JSON.stringify({
      ...envelope, intent: { ...envelope.intent, expectedEpochId: "epoch:stale" },
    });
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("Signing context changed"));
    expect(fetchImpl.mock.calls.some(([input]) => new URL(String(input)).pathname === "/v1/mutations")).toBe(false);
    expect(root.querySelector<HTMLButtonElement>("[data-signed-submit] button")?.disabled).toBe(true);
  });
});
