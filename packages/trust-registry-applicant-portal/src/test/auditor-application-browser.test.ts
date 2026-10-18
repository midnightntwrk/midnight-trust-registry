// @vitest-environment happy-dom
import { computeAuthorizationScopeCommitment, requestGovernedResourceId } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it, vi } from "vitest";

import { createApplicantPortalApp } from "../app.js";

const did = `did:midnight:undeployed:${"1".repeat(64)}`;
const applicationId = "application:auditor:compliance:v1";
const authorizationId = "auth:auditor:compliance:v1";
const context = {
  registryId: "registry:test:trusted",
  expectedEpochId: "epoch:registry:test:trusted:seq-1",
  expectedWorkspaceCommitment: `0x${"b".repeat(64)}`,
  evaluatedAt: "2026-10-15T05:00:00.000Z",
};

describe("structured auditor application in the applicant portal", () => {
  it("prepares an exact-scope external signature and submits it without retaining the signature", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const registered: unknown[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path === "/v1/registry/mutation-context") return Response.json(context);
      if (path === "/v1/pending-applications") {
        const request: unknown = JSON.parse(String(init?.body));
        registered.push(request);
        const signed = request as { applicationId: string; authorizationId: string; scope: { role: string }; governedResource: { type: string; id: string }; intent: { actorDid: string; scopeCommitment: string } };
        return Response.json({
          authorizationId: signed.authorizationId,
          status: "pending",
          binding: {
            registryId: context.registryId,
            applicationId: signed.applicationId,
            subjectDid: signed.intent.actorDid,
            evidenceVerifierDid: did,
            role: signed.scope.role,
            scope: signed.scope,
            scopeCommitment: signed.intent.scopeCommitment,
            policyId: "policy:one",
            policyVersion: "v1",
            governedResource: signed.governedResource,
          },
        });
      }
      if (path === "/v1/registry/summary") return Response.json({ registryLabel: "local", currentEpochId: context.expectedEpochId });
      return Response.json({ entries: [] });
    });
    createApplicantPortalApp(root, {
      initialUrl: new URL("https://registry.example/app?apiBase=https%3A%2F%2Fregistry.example"),
      storage: { getItem: () => null, setItem: vi.fn() } as unknown as Storage,
      fetchImpl: fetchImpl as typeof fetch,
    });
    const form = root.querySelector<HTMLFormElement>("[data-auditor-application-form]")!;
    const field = (name: string, value: string) => {
      form.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name='${name}']`)!.value = value;
    };
    field("applicationId", applicationId);
    field("authorizationId", authorizationId);
    field("actorDid", did);
    field("actorKeyId", `${did}#authentication-1`);
    field("requestProfileId", "profile:compliance:v1");
    field("purpose", "regulated-audit");
    field("credentialScopeCommitment", `0x${"a".repeat(64)}`);
    field("allowedAttributes", "attribute:age\nattribute:residency");
    field("allowedPredicates", "predicate:over-18");
    field("disclosureLevel", "minimal");
    form.querySelector<HTMLButtonElement>("[data-prepare-auditor]")!.click();
    await vi.waitFor(() => expect(root.querySelector("[data-auditor-digest]")?.textContent).toMatch(/^Sign digest bytes: 0x[0-9a-f]{64}$/u));
    expect(registered).toHaveLength(0);
    const signature = `0x${"d".repeat(192)}`;
    const preparedForm = root.querySelector<HTMLFormElement>("[data-auditor-application-form]")!;
    preparedForm.querySelector<HTMLInputElement>("[name='auditorSignature']")!.value = signature;
    preparedForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.textContent).toContain("Pending auditor application"));
    expect(registered).toHaveLength(1);
    const submitted = registered[0] as { scope: Parameters<typeof requestGovernedResourceId>[0]; governedResource: { id: string }; intent: { actorRole: string; action: string; target: string; scopeCommitment: string }; signature: { value: string } };
    expect(submitted.governedResource.id).toBe(requestGovernedResourceId(submitted.scope));
    expect(submitted.intent).toMatchObject({
      actorRole: "applicant", action: "apply", target: "auditor",
      scopeCommitment: computeAuthorizationScopeCommitment(submitted.scope),
    });
    expect(submitted.signature.value).toBe(signature);
    expect(root.innerHTML).not.toContain(signature);
    expect(root.querySelector("[data-auditor-digest]")).toBeNull();
  });
});
