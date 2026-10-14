// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { createApplicantPortalApp } from "../app.js";

const counts = () => ({ proposed: 0, authorized: 0, active: 0, suspended: 0, revoked: 0,
  superseded: 0, archived: 0 });

describe("accredited recognition recovery", () => {
  it("discards a late challenge when the authenticated host changes", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    window.localStorage.clear();
    let finishChallenge: ((response: Response) => void) | undefined;
    const challengeResponse = new Promise<Response>((resolve) => { finishChallenge = resolve; });
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/challenges")) return challengeResponse;
      if (path === "/v1/registry/summary") return Response.json({ issuerCounts: counts(),
        verifierCounts: counts(), auditorCounts: counts(), recognitionCounts: counts(),
        currentEpochId: "epoch:1", registryLabel: "local", registryId: "registry:local",
        registryDid: "did:midnight:testnet:registry", policyId: "policy:local", epochCount: 1 });
      return Response.json({ entries: [] });
    });
    createApplicantPortalApp(root, { initialUrl: new URL("http://127.0.0.1:4400/"),
      storage: window.localStorage, fetchImpl: fetchImpl as typeof fetch });
    await vi.waitFor(() => expect(root.querySelector("[data-recognition-challenge]")
      ?.hasAttribute("disabled")).toBe(false));
    root.querySelector<HTMLInputElement>("[data-recognition-recovery-form] [name='recognitionId']")!
      .value = "recognition:partner";
    root.querySelector<HTMLButtonElement>("[data-recognition-challenge]")!.click();
    await vi.waitFor(() => expect(finishChallenge).toBeTypeOf("function"));
    root.querySelector<HTMLInputElement>("[data-api-base-form] [name='apiBase']")!
      .value = "http://127.0.0.1:4400/next";
    root.querySelector<HTMLFormElement>("[data-api-base-form]")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    finishChallenge!(Response.json({ recognitionId: "recognition:partner", nonce: "stale-nonce",
      challengeHash: `0x${"44".repeat(32)}`, issuedAt: "2026-10-15T00:00:00Z",
      expiresAt: "2026-10-15T00:10:00Z" }));
    await vi.waitFor(() => expect(root.querySelector("[data-recognition-challenge-context]")).toBeNull());
    expect(root.textContent).not.toContain("stale-nonce");
  });

  it("completes the private challenge, external-signature submission, and accepted receipt journey", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const nonce = `0x${"33".repeat(32)}`;
    const receipt = { receiptId: `0x${"11".repeat(32)}`, recognitionId: "recognition:partner",
      evidenceCommitment: `0x${"22".repeat(32)}` };
    const submissions: unknown[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/challenges")) return Response.json({ recognitionId: "recognition:partner",
        nonce, challengeHash: `0x${"44".repeat(32)}`, issuedAt: "2026-10-15T00:00:00Z",
        expiresAt: "2026-10-15T00:10:00Z" });
      if (path.endsWith("/submissions")) {
        submissions.push(JSON.parse(String(init?.body)));
        return Response.json({ recognitionId: "recognition:partner", evidenceCommitment: receipt.evidenceCommitment,
          receipt, expiresAt: "2026-10-15T00:10:00Z" });
      }
      if (path.endsWith("/accepted")) return Response.json(receipt);
      if (path === "/v1/registry/summary") return Response.json({ issuerCounts: counts(),
        verifierCounts: counts(), auditorCounts: counts(), recognitionCounts: counts(),
        currentEpochId: "epoch:1", registryLabel: "local", registryId: "registry:local",
        registryDid: "did:midnight:testnet:registry", policyId: "policy:local", epochCount: 1 });
      return Response.json({ entries: [] });
    });
    createApplicantPortalApp(root, { initialUrl: new URL("http://127.0.0.1:4400/"),
      storage: window.localStorage, fetchImpl: fetchImpl as typeof fetch });
    await vi.waitFor(() => expect(root.querySelector("[data-recognition-challenge]")
      ?.hasAttribute("disabled")).toBe(false));
    root.querySelector<HTMLInputElement>("[data-recognition-recovery-form] [name='recognitionId']")!
      .value = "recognition:partner";
    root.querySelector<HTMLButtonElement>("[data-recognition-challenge]")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain(nonce));
    const submission = { nonce, signed: { statement: "externally-signed" },
      accreditation: { rawPresentationBody: "private-vp" } };
    const textarea = root.querySelector<HTMLTextAreaElement>("[data-recognition-accreditation-form] textarea")!;
    textarea.value = JSON.stringify({ ...submission, nonce: `0x${"55".repeat(32)}` });
    root.querySelector<HTMLFormElement>("[data-recognition-accreditation-form]")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("current challenge nonce"));
    expect(submissions).toHaveLength(0);
    expect(textarea.value).toBe("");
    root.querySelector<HTMLTextAreaElement>("[data-recognition-accreditation-form] textarea")!
      .value = JSON.stringify(submission);
    root.querySelector<HTMLFormElement>("[data-recognition-accreditation-form]")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("Recognition accreditation accepted"));
    expect(submissions).toEqual([submission]);
    expect(root.innerHTML).not.toContain("private-vp");
    expect(root.querySelector<HTMLInputElement>("[data-recognition-recovery-form] [name='receiptId']")?.value)
      .toBe(receipt.receiptId);
    root.querySelector<HTMLButtonElement>("[data-recognition-accepted]")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain("Accepted accreditation receipt recovered"));
    const recognitionIdInput = root.querySelector<HTMLInputElement>("[data-recognition-recovery-form] [name='recognitionId']")!;
    recognitionIdInput.value = "recognition:other";
    recognitionIdInput.dispatchEvent(new Event("input", { bubbles: true }));
    expect(root.querySelector("[data-recognition-admission]")).toBeNull();
  });

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
