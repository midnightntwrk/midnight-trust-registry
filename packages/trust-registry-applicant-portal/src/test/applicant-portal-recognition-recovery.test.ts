// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { createApplicantPortalApp } from "../app.js";

const counts = () => ({ proposed: 0, authorized: 0, active: 0, suspended: 0, revoked: 0,
  superseded: 0, archived: 0 });

describe("accredited recognition recovery", () => {
  it("requires a same-origin host and never retries an unobserved proposal", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    window.localStorage.clear();
    const requests: { path: string; init: RequestInit }[] = [];
    let observed = false;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/proposal/resolve")) {
        requests.push({ path, init: init! });
        return Response.json(observed
          ? { state: "observed", eventHash: `0x${"ab".repeat(32)}` }
          : { state: "not-observed" });
      }
      if (path === "/v1/registry/summary") {
        return Response.json({ issuerCounts: counts(), verifierCounts: counts(), auditorCounts: counts(),
          recognitionCounts: counts(), currentEpochId: "epoch:1", registryLabel: "local",
          registryId: "registry:local", registryDid: "did:midnight:testnet:registry", policyId: "policy:local",
          epochCount: 1 });
      }
      return Response.json({ entries: [] });
    });
    createApplicantPortalApp(root, {
      initialUrl: new URL("http://127.0.0.1:4400/"),
      storage: window.localStorage,
      fetchImpl: fetchImpl as typeof fetch,
    });
    await vi.waitFor(() => expect(root.querySelector("[data-recognition-recovery-form] button")
      ?.hasAttribute("disabled")).toBe(false));
    const fill = (name: string, value: string) => {
      root.querySelector<HTMLInputElement>(`[data-recognition-recovery-form] [name="${name}"]`)!.value = value;
    };
    const submit = () => root.querySelector<HTMLFormElement>("[data-recognition-recovery-form]")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    fill("recognitionId", "recognition:partner");
    fill("receiptId", `0x${"11".repeat(32)}`);
    fill("evidenceCommitment", `0x${"22".repeat(32)}`);
    submit();
    await vi.waitFor(() => expect(root.textContent).toContain("do not resubmit automatically"));
    expect(requests).toHaveLength(1);
    expect(requests[0]?.path).toBe("/v1/governed/recognition/recognition%3Apartner/proposal/resolve");
    expect(requests[0]?.init.credentials).toBe("same-origin");
    expect(JSON.parse(String(requests[0]?.init.body))).toEqual({
      receiptId: `0x${"11".repeat(32)}`, evidenceCommitment: `0x${"22".repeat(32)}`,
    });
    expect(window.localStorage.length).toBe(0);
    observed = true;
    fill("recognitionId", "recognition:partner");
    fill("receiptId", `0x${"11".repeat(32)}`);
    fill("evidenceCommitment", `0x${"22".repeat(32)}`);
    submit();
    await vi.waitFor(() => expect(root.textContent).toContain("Compact recognition proposal observed"));
  });

  it("disables private recovery for a cross-origin API", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const fetchImpl = vi.fn(async () => Response.json({ entries: [] }));
    createApplicantPortalApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=https://registry.example"),
      storage: window.localStorage,
      fetchImpl: fetchImpl as typeof fetch,
    });
    expect(root.querySelector("[data-recognition-recovery-form] button")?.hasAttribute("disabled")).toBe(true);
  });
});
