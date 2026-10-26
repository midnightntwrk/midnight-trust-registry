// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { createAdminConsoleApp } from "../app.js";

const hash = `0x${"a".repeat(64)}`;
const counts = { proposed: 0, authorized: 0, active: 0, suspended: 0, revoked: 0, superseded: 0, archived: 0 };
const summary = {
  registryLabel: "local", currentEpochId: "epoch:local:1",
  issuerCounts: counts, verifierCounts: counts, auditorCounts: counts, recognitionCounts: counts,
};
const signer = { keyId: hash, publicKey: { x: "1", y: "2" }, signature: "0x0102" };

describe("admin governed policy controls", () => {
  it("invalidates changed thresholds and requires separate registration after revision", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const calls: Array<{ path: string; body: unknown }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path === "/health") return Response.json({ status: "ok", sourceMode: "workspace", registryId: "registry:local" });
      if (path === "/v1/registry/summary") return Response.json(summary);
      if (path.startsWith("/v1/authorizations/") || path === "/v1/recognitions") {
        return Response.json({ entries: [] });
      }
      const body = JSON.parse(String(init?.body)) as unknown;
      calls.push({ path, body });
      if (path.endsWith("/prepare")) return Response.json({
        registryId: hash, policyCommitment: hash, actionKind: hash,
        actionPayloadHash: hash, actionSequence: path.includes("thresholds") ? "3" : "4",
      });
      return Response.json({ eventHash: hash }, { status: 202 });
    });
    const confirm = vi.fn(() => true);
    createAdminConsoleApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch,
      confirm,
    });
    await vi.waitFor(() => expect(
      root.querySelector<HTMLButtonElement>("[data-policy-prepare-thresholds]")?.disabled,
    ).toBe(false));

    root.querySelector<HTMLButtonElement>("[data-policy-prepare-thresholds]")!.click();
    await vi.waitFor(() => expect(root.querySelector("[data-policy-context]")).not.toBeNull());
    root.querySelector<HTMLButtonElement>("[data-refresh]")!.click();
    await vi.waitFor(() => expect(root.querySelector("[data-policy-context]")).toBeNull());
    await vi.waitFor(() => expect(
      root.querySelector<HTMLButtonElement>("[data-policy-prepare-thresholds]")?.disabled,
    ).toBe(false));
    root.querySelector<HTMLButtonElement>("[data-policy-prepare-thresholds]")!.click();
    await vi.waitFor(() => expect(root.querySelector("[data-policy-context]")).not.toBeNull());
    const threshold = root.querySelector<HTMLInputElement>("[data-policy-threshold='default']")!;
    threshold.value = "3";
    threshold.dispatchEvent(new Event("input", { bubbles: true }));
    expect(root.querySelector("[data-policy-context]")).toBeNull();
    expect(root.querySelector("[data-policy-submit]")).toBeNull();

    root.querySelector<HTMLButtonElement>("[data-policy-prepare-thresholds]")!.click();
    await vi.waitFor(() => expect(root.querySelector("[data-policy-context]")).not.toBeNull());
    const revisionForm = root.querySelector<HTMLFormElement>("[data-policy-submit]")!;
    const revisionSigners = revisionForm.querySelector<HTMLTextAreaElement>("[data-policy-signers]")!;
    revisionSigners.value = JSON.stringify([signer]);
    revisionSigners.dispatchEvent(new Event("input", { bubbles: true }));
    revisionForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("registration is still required"));
    expect(calls.filter((call) => call.path.endsWith("thresholds/submit")).at(-1)?.body).toMatchObject({
      thresholds: { default: "3", emergency: "2", archival: "2" },
      signers: [signer],
    });

    root.querySelector<HTMLButtonElement>("[data-policy-prepare-verifier]")!.click();
    await vi.waitFor(() => expect(root.querySelector("[data-policy-context]")).not.toBeNull());
    const registrationForm = root.querySelector<HTMLFormElement>("[data-policy-submit]")!;
    const registrationSigners = registrationForm.querySelector<HTMLTextAreaElement>("[data-policy-signers]")!;
    registrationSigners.value = JSON.stringify([signer]);
    registrationSigners.dispatchEvent(new Event("input", { bubbles: true }));
    registrationForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("Evidence-verifier registration accepted"));
    expect(root.textContent).not.toContain("registration is still required");
    expect(calls.filter((call) => call.path.endsWith("evidence-verifier/submit")).at(-1)?.body)
      .toMatchObject({ signers: [signer] });
    expect(confirm).toHaveBeenCalledTimes(2);
  });
});
