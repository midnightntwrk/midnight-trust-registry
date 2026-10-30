// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { createApplicantPortalApp } from "../app.js";

const did = `did:midnight:undeployed:${"1".repeat(64)}`;
const hash = `0x${"a".repeat(64)}`;
const context = {
  registryId: "registry:test:trusted",
  expectedEpochId: "epoch:registry:test:trusted:seq-1",
  expectedWorkspaceCommitment: hash,
};
const envelope = {
  intent: {
    version: "tr-mutation-intent-v1", registryId: context.registryId,
    actorDid: did, actorKeyId: `${did}#assertion-1`, actorRole: "applicant",
    action: "submit", target: "issuer", targetId: "auth:issuer:degree:v1",
    scopeCommitment: hash, payloadCommitment: hash, nonce: hash,
    expectedWorkspaceCommitment: context.expectedWorkspaceCommitment,
    expectedEpochId: context.expectedEpochId,
    issuedAt: "2026-10-10T00:00:00.000Z", expiresAt: "2026-10-10T00:05:00.000Z",
  },
  signature: { keyId: `${did}#assertion-1`, algorithm: "jubjub-schnorr", value: `0x${"b".repeat(192)}` },
  operation: { operation: "submit", target: "issuer", label: "degree" },
};

describe("applicant signed browser journey", () => {
  it("loads context and forwards an external signature without displaying or retaining it", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const calls: Array<{ path: string; init: RequestInit | undefined }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      calls.push({ path, init });
      if (path === "/v1/registry/mutation-context") return Response.json(context);
      if (path === "/v1/mutations") return Response.json({
        recordKind: "authorization", operation: envelope.operation,
      });
      if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local", currentEpochId: context.expectedEpochId });
      return Response.json({ entries: [] });
    });
    createApplicantPortalApp(root, {
      initialUrl: new URL("http://127.0.0.1:4175/?apiBase=http://127.0.0.1:4400"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch,
    });
    await vi.waitFor(() => expect(root.textContent).toContain("Signed issuer or verifier submission"));
    expect(root.querySelector<HTMLButtonElement>("[data-signed-submit] button")?.disabled).toBe(true);
    await vi.waitFor(() => expect(root.querySelector<HTMLButtonElement>("[data-signed-context]")).not.toBeNull());
    root.querySelector<HTMLButtonElement>("[data-signed-context]")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain(context.expectedWorkspaceCommitment));
    expect(calls.find((call) => call.path === "/v1/registry/mutation-context")?.init).toEqual({ cache: "no-store" });
    const form = root.querySelector<HTMLFormElement>("[data-signed-submit]")!;
    form.querySelector<HTMLTextAreaElement>("[name='signedEnvelope']")!.value = JSON.stringify(envelope);
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("Signed submit accepted for issuer"));
    expect(calls.find((call) => call.path === "/v1/mutations")?.init?.body).toBe(JSON.stringify(envelope));
    expect(root.innerHTML).not.toContain(envelope.signature.value);
    expect(root.querySelector<HTMLTextAreaElement>("[name='signedEnvelope']")?.value).toBe("");
    expect(root.querySelector<HTMLButtonElement>("[data-signed-submit] button")?.disabled).toBe(true);
  });

  it("rejects mismatched context before posting and requires another context", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path === "/v1/registry/mutation-context") return Response.json(context);
      if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local", currentEpochId: context.expectedEpochId });
      return Response.json({ entries: [] });
    });
    createApplicantPortalApp(root, {
      initialUrl: new URL("http://127.0.0.1:4175/?apiBase=http://127.0.0.1:4400"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch,
    });
    await vi.waitFor(() => expect(root.querySelector<HTMLButtonElement>("[data-signed-context]")).not.toBeNull());
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
