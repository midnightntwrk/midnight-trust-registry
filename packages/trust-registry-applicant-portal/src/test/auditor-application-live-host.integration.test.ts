// @vitest-environment happy-dom
import { request as httpRequest, type Server } from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";

import { createApplicantPortalApp } from "../app.js";

type DemoHost = { server: Server; base: string; cookie: string; receipts: Map<string, unknown> };
type DemoModule = {
  applicationDraft: Record<string, string | string[]>;
  startHost: (port: number, staticDir: string) => Promise<DemoHost>;
  signDigest: (digest: string) => string;
  presentationForNonce: (nonce: string) => Promise<unknown>;
};

describe("auditor applicant form with the live admission host", () => {
  it("prepares, externally signs, registers, and presents evidence through real HTTP routes", async () => {
    const demoPath = pathToFileURL(resolve(process.cwd(), "../../scripts/demo-auditor-admission.mjs"));
    const demo = await import(demoPath.href) as DemoModule;
    const host = await demo.startHost(0, resolve(process.cwd(), "dist"));
    try {
      const root = document.createElement("div");
      document.body.replaceChildren(root);
      const calls: Array<{ path: string; method: string; body: string | undefined }> = [];
      const registrationStatuses: number[] = [];
      let challengeNonce: string | undefined;
      const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = new URL(String(input));
        const method = init?.method ?? "GET";
        const headers = new Headers(init?.headers);
        headers.set("cookie", host.cookie);
        if (method === "POST") headers.set("origin", host.base);
        calls.push({ path: url.pathname, method, body: typeof init?.body === "string" ? init.body : undefined });
        const response = await new Promise<Response>((resolveResponse, rejectResponse) => {
          const request = httpRequest(url, { method, headers: Object.fromEntries(headers.entries()) }, (incoming) => {
            const status = incoming.statusCode;
            if (status === undefined) {
              incoming.resume();
              rejectResponse(new Error("Demo host returned no HTTP status"));
              return;
            }
            const chunks: Buffer[] = [];
            incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
            incoming.on("error", rejectResponse);
            incoming.on("end", () => resolveResponse(new Response(Buffer.concat(chunks), {
              status,
              headers: incoming.headers as HeadersInit,
            })));
          });
          request.on("error", rejectResponse);
          request.end(init?.body === undefined ? undefined : String(init.body));
        });
        if (url.pathname === "/v1/pending-applications") registrationStatuses.push(response.status);
        if (url.pathname.endsWith("/challenges") && response.ok) {
          challengeNonce = (await response.clone().json() as { nonce: string }).nonce;
        }
        return response;
      });
      createApplicantPortalApp(root, {
        initialUrl: new URL(`${host.base}/?apiBase=${encodeURIComponent(host.base)}`),
        storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
        fetchImpl: fetchImpl as typeof fetch,
      });
      await vi.waitFor(() => expect(root.textContent).toContain("Auditor request"), { timeout: 5000 });
      const form = root.querySelector<HTMLFormElement>("[data-auditor-application-form]")!;
      for (const [name, value] of Object.entries(demo.applicationDraft)) {
        form.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name='${name}']`)!.value =
          Array.isArray(value) ? value.join("\n") : value;
      }
      form.querySelector<HTMLButtonElement>("[data-prepare-auditor]")!.click();
      await vi.waitFor(() => expect(root.querySelector("[data-auditor-digest]")?.textContent)
        .toMatch(/^Sign digest bytes: 0x[0-9a-f]{64}$/u), { timeout: 5000 });
      const digest = root.querySelector("[data-auditor-digest]")!.textContent!.split(": ")[1]!;
      const signature = demo.signDigest(digest);
      const submitSignature = (value: string) => {
        const preparedForm = root.querySelector<HTMLFormElement>("[data-auditor-application-form]")!;
        preparedForm.querySelector<HTMLInputElement>("[name='auditorSignature']")!.value = value;
        preparedForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      };
      submitSignature(`0x${"00".repeat(96)}`);
      await vi.waitFor(() => expect(registrationStatuses).toHaveLength(1), { timeout: 5000 });
      expect(registrationStatuses[0]).not.toBe(201);
      expect(host.receipts.size).toBe(0);
      submitSignature(signature);
      await vi.waitFor(() => expect(root.textContent).toContain("Pending auditor application"), { timeout: 5000 });
      expect(registrationStatuses[1]).toBe(201);
      expect(calls.filter(({ path }) => path === "/v1/pending-applications")).toHaveLength(2);
      expect(root.innerHTML).not.toContain(signature);
      expect(root.querySelector("[data-auditor-status]")?.textContent).toContain("not active");

      const bindingForm = root.querySelector<HTMLFormElement>("[data-application-binding-form]")!;
      bindingForm.querySelector<HTMLInputElement>("[name='applicationId']")!.value =
        String(demo.applicationDraft.applicationId);
      bindingForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      await vi.waitFor(() => expect(root.textContent).toContain(String(demo.applicationDraft.requestProfileId)), { timeout: 5000 });
      root.querySelector<HTMLButtonElement>("[data-application-challenge]")!.click();
      await vi.waitFor(() => expect(challengeNonce).toMatch(/^0x[0-9a-f]{64}$/u), { timeout: 5000 });
      const presentation = await demo.presentationForNonce(challengeNonce!);
      const vpForm = root.querySelector<HTMLFormElement>("[data-application-vp-form]")!;
      vpForm.querySelector<HTMLTextAreaElement>("[name='presentation']")!.value = JSON.stringify(presentation);
      vpForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      await vi.waitFor(() => expect(root.textContent).toContain("auditor evidence accepted"), { timeout: 5000 });
      expect(host.receipts.size).toBe(1);
      expect(root.innerHTML).not.toContain("private-presentation-payload");
      expect(root.querySelector("[data-application-vp-form]")).toBeNull();
      expect(calls.filter(({ path }) => path.endsWith("/submissions"))).toHaveLength(1);
    } finally {
      await new Promise<void>((resolveClose, reject) => host.server.close((error) => error ? reject(error) : resolveClose()));
    }
  }, 45_000);
});
