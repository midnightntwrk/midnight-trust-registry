// @vitest-environment happy-dom
import { request as httpRequest, type Server } from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";

import { createApplicantPortalApp } from "../app.js";

type DemoHost = { server: Server; base: string; cookie: string; receipts: Map<string, unknown> };
type DemoModule = {
  applicationDraft: { actorDid: string; actorKeyId: string };
  startHost: (port: number, staticDir: string, scope: unknown) => Promise<DemoHost>;
  signDigest: (digest: string) => string;
  presentationForNonce: (nonce: string, scope: unknown) => Promise<unknown>;
};

const cases = [
  {
    role: "issuer",
    applicationId: "application:issuer:local-form:v1",
    authorizationId: "auth:issuer:local-form:v1",
    scope: {
      version: "tr-scope-v1", role: "issuer", credentialFamilyId: "family:degree:v1",
      schemaId: "schema:degree", schemaVersion: "1.0.0",
      credentialDefinitionId: "definition:degree:v1", statusMethod: "status:registry:v1",
    },
    governedResourceType: "credentialFamily",
  },
  {
    role: "verifier",
    applicationId: "application:verifier:local-form:v1",
    authorizationId: "auth:verifier:local-form:v1",
    scope: {
      version: "tr-scope-v1", role: "verifier", requestProfileId: "profile:age-gate:v1",
      purpose: "age-gate", credentialScopeCommitment: `0x${"a".repeat(64)}`,
      allowedAttributes: ["attribute:age"], allowedPredicates: ["predicate:over-18"],
      disclosureLevel: "minimal",
    },
  },
] as const;

describe("issuer and verifier forms with the live admission host", () => {
  for (const applicant of cases) {
    it(`${applicant.role} registers and presents evidence using real HTTP signature verification`, async () => {
      const demoPath = pathToFileURL(resolve(process.cwd(), "../../scripts/demo-auditor-admission.mjs"));
      const demo = await import(demoPath.href) as DemoModule;
      const host = await demo.startHost(0, resolve(process.cwd(), "dist"), applicant.scope);
      try {
        const root = document.createElement("div");
        document.body.replaceChildren(root);
        const registrationStatuses: number[] = [];
        let challengeNonce: string | undefined;
        const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
          const url = new URL(String(input));
          const method = init?.method ?? "GET";
          const headers = new Headers(init?.headers);
          headers.set("cookie", host.cookie);
          if (method === "POST") headers.set("origin", host.base);
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
                status, headers: incoming.headers as HeadersInit,
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
        const form = root.querySelector<HTMLFormElement>(`[data-${applicant.role}-application-form]`)!;
        const fields = {
          applicationId: applicant.applicationId, authorizationId: applicant.authorizationId,
          actorDid: demo.applicationDraft.actorDid, actorKeyId: demo.applicationDraft.actorKeyId,
          ...applicant.scope, ...("governedResourceType" in applicant ? { governedResourceType: applicant.governedResourceType } : {}),
        };
        for (const [name, value] of Object.entries(fields)) {
          if (name === "version" || name === "role") continue;
          form.querySelector<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(`[name='${name}']`)!.value =
            typeof value === "string" ? value : value.join("\n");
        }
        form.querySelector<HTMLButtonElement>(`[data-prepare-${applicant.role}]`)!.click();
        await vi.waitFor(() => expect(root.querySelector(`[data-${applicant.role}-digest]`)?.textContent)
          .toMatch(/^Sign digest bytes: 0x[0-9a-f]{64}$/u), { timeout: 5000 });
        const digest = root.querySelector(`[data-${applicant.role}-digest]`)!.textContent!.split(": ")[1]!;
        const signature = demo.signDigest(digest);
        const submitSignature = (value: string) => {
          const preparedForm = root.querySelector<HTMLFormElement>(`[data-${applicant.role}-application-form]`)!;
          preparedForm.querySelector<HTMLInputElement>("[name='memberSignature']")!.value = value;
          preparedForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
        };
        submitSignature(`0x${"00".repeat(96)}`);
        await vi.waitFor(() => expect(registrationStatuses).toHaveLength(1), { timeout: 5000 });
        expect(registrationStatuses[0]).not.toBe(201);
        expect(host.receipts.size).toBe(0);
        submitSignature(signature);
        await vi.waitFor(() => expect(root.textContent).toContain(`Pending ${applicant.role} application`), { timeout: 5000 });
        expect(registrationStatuses[1]).toBe(201);
        expect(root.innerHTML).not.toContain(signature);

        const bindingForm = root.querySelector<HTMLFormElement>("[data-application-binding-form]")!;
        bindingForm.querySelector<HTMLInputElement>("[name='applicationId']")!.value = applicant.applicationId;
        bindingForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
        await vi.waitFor(() => expect(root.textContent).toContain(applicant.scope.role === "issuer"
          ? applicant.scope.credentialFamilyId : applicant.scope.requestProfileId), { timeout: 5000 });
        root.querySelector<HTMLButtonElement>("[data-application-challenge]")!.click();
        await vi.waitFor(() => expect(challengeNonce).toMatch(/^0x[0-9a-f]{64}$/u), { timeout: 5000 });
        const presentation = await demo.presentationForNonce(challengeNonce!, applicant.scope);
        const vpForm = root.querySelector<HTMLFormElement>("[data-application-vp-form]")!;
        vpForm.querySelector<HTMLTextAreaElement>("[name='presentation']")!.value = JSON.stringify(presentation);
        vpForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
        await vi.waitFor(() => expect(root.textContent).toContain(`${applicant.role} evidence accepted`), { timeout: 5000 });
        expect(host.receipts.size).toBe(1);
        expect(root.innerHTML).not.toContain("private-presentation-payload");
      } finally {
        await new Promise<void>((resolveClose, reject) => host.server.close((error) => error ? reject(error) : resolveClose()));
      }
    }, 20_000);
  }
});
