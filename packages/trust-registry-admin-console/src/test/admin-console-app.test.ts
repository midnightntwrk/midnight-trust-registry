// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { createAdminConsoleApp } from "../app.js";

const counts = () => ({
  proposed: 0,
  authorized: 0,
  active: 0,
  suspended: 0,
  revoked: 0,
  superseded: 0,
  archived: 0,
});

const auditor = {
  label: "compliance",
  authorization: {
    authorizationId: "auth:auditor:compliance",
    registryId: "registry:local",
    role: "auditor",
    subjectDid: "did:midnight:testnet:auditor",
    resourceType: "request-profile",
    resourceId: `tr:request-resource:v1:${"a".repeat(64)}`,
    policyId: "policy:local",
    trustLevel: "approved",
    status: "active",
    proposedAt: "2026-10-08T00:00:00Z",
    activeFrom: "2026-10-08T01:00:00Z",
  },
  evidence: {
    epoch: { epochId: "epoch:1", stateRoot: "state-root" },
  },
};

describe("admin console browser handlers", () => {
  it("loads auditor cards and confirms actions and epoch publication before POST", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const confirm = vi.fn(() => false);
    const postedPaths: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (init?.method === "POST") {
        postedPaths.push(path);
        return Response.json({
          recordKind: "epoch",
          epoch: { epochId: "epoch:2" },
        });
      }
      if (path === "/v1/registry/summary") {
        return Response.json({
          issuerCounts: counts(),
          verifierCounts: counts(),
          auditorCounts: { ...counts(), active: 1 },
          recognitionCounts: counts(),
          currentEpochId: "epoch:1",
          registryLabel: "local",
          registryId: "registry:local",
          registryDid: "did:midnight:testnet:registry",
          policyId: "policy:local",
          epochCount: 1,
        });
      }
      return Response.json({ entries: path === "/v1/authorizations/auditor" ? [auditor] : [] });
    });
    createAdminConsoleApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400"),
      storage: window.localStorage,
      fetchImpl: fetchImpl as typeof fetch,
      confirm,
    });

    await vi.waitFor(() => expect(root.textContent).toContain(auditor.authorization.resourceId));
    root.querySelector<HTMLButtonElement>("[data-action='suspend']")!.click();
    await vi.waitFor(() => expect(confirm).toHaveBeenCalledWith(
      expect.stringContaining("auditor record auth:auditor:compliance"),
    ));
    await vi.waitFor(() => expect(root.querySelector("[data-action='suspend']")?.hasAttribute("disabled")).toBe(false));
    expect(postedPaths).toEqual([]);

    root.querySelector<HTMLFormElement>("[data-epoch-form]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(confirm).toHaveBeenCalledWith(
      expect.stringContaining("anchors the current state root"),
    ));
    await vi.waitFor(() => expect(root.querySelector("[data-epoch-form] button")?.hasAttribute("disabled")).toBe(false));
    expect(postedPaths).toEqual([]);

    confirm.mockReturnValue(true);
    root.querySelector<HTMLFormElement>("[data-epoch-form]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(postedPaths).toEqual(["/v1/epochs/publish"]));
  });
});
