// @vitest-environment happy-dom
import { computeAuthorizationScopeCommitment, issuerGovernedResourceId, requestGovernedResourceId } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it, vi } from "vitest";

import { createApplicantPortalApp } from "../app.js";

const did = `did:midnight:undeployed:${"1".repeat(64)}`;
const context = {
  registryId: "registry:test:trusted",
  expectedEpochId: "epoch:registry:test:trusted:seq-1",
  expectedWorkspaceCommitment: `0x${"b".repeat(64)}`,
  evaluatedAt: "2026-10-15T05:00:00.000Z",
};
const cases = [
  {
    role: "issuer",
    draft: {
      applicationId: "application:issuer:degree:v1", authorizationId: "auth:issuer:degree:v1",
      actorDid: did, actorKeyId: `${did}#authentication-1`,
      credentialFamilyId: "family:degree:v1", schemaId: "schema:degree", schemaVersion: "1.0.0",
      credentialDefinitionId: "definition:degree:v1", statusMethod: "status:registry:v1",
      governedResourceType: "credentialFamily",
    },
  },
  {
    role: "verifier",
    draft: {
      applicationId: "application:verifier:age-gate:v1", authorizationId: "auth:verifier:age-gate:v1",
      actorDid: did, actorKeyId: `${did}#authentication-1`,
      requestProfileId: "profile:age-gate:v1", purpose: "age-gate",
      credentialScopeCommitment: `0x${"a".repeat(64)}`,
      allowedAttributes: ["attribute:age"], allowedPredicates: ["predicate:over-18"], disclosureLevel: "minimal",
    },
  },
  {
    role: "maintainer",
    draft: {
      applicationId: "application:maintainer:one:v1", authorizationId: "auth:maintainer:one:v1",
      actorDid: did, actorKeyId: `${did}#authentication-1`,
    },
  },
] as const;

describe("structured membership forms", () => {
  for (const { role, draft } of cases) {
    it(`${role} prepares a signed request and refuses a substituted host scope`, async () => {
      const root = document.createElement("div");
      document.body.replaceChildren(root);
      const submitted: Array<{ scope: Record<string, unknown>; governedResource: { type: string; id: string }; intent: { actorDid: string; target: string; expectedEpochId: string }; signature: { value: string }; applicationId: string; authorizationId: string }> = [];
      let substitution: "scope" | "registry" | undefined = "scope";
      const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const path = new URL(String(input)).pathname;
        if (path === "/v1/registry/mutation-context") return Response.json(context);
        if (path === "/v1/pending-applications") {
          const signed = JSON.parse(String(init?.body)) as typeof submitted[number];
          submitted.push(signed);
          return Response.json({
            authorizationId: signed.authorizationId,
            status: "pending",
            binding: {
              registryId: substitution === "registry" ? "registry:other:trusted" : context.registryId,
              applicationId: signed.applicationId,
              subjectDid: signed.intent.actorDid,
              evidenceVerifierDid: did,
              role,
              scope: substitution === "scope" ? { ...signed.scope, ...(role === "issuer"
                ? { schemaId: "schema:substituted" }
                : role === "verifier" ? { purpose: "substituted" } : { registryId: "registry:other:trusted" }) } : signed.scope,
              scopeCommitment: computeAuthorizationScopeCommitment(signed.scope as Parameters<typeof computeAuthorizationScopeCommitment>[0]),
              policyId: "policy:one", policyVersion: "v1",
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
      const form = root.querySelector<HTMLFormElement>(`[data-${role}-application-form]`)!;
      for (const [name, value] of Object.entries(draft)) {
        const input = form.querySelector<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(`[name='${name}']`)!;
        input.value = typeof value === "string" ? value : value.join("\n");
      }
      form.querySelector<HTMLButtonElement>(`[data-prepare-${role}]`)!.click();
      await vi.waitFor(() => expect(root.querySelector(`[data-${role}-digest]`)?.textContent)
        .toMatch(/^Sign digest bytes: 0x[0-9a-f]{64}$/u));
      root.querySelector<HTMLButtonElement>(`[data-${role}-application-form] [data-reset-member]`)!.click();
      expect(root.querySelector(`[data-${role}-digest]`)).toBeNull();
      root.querySelector<HTMLButtonElement>(`[data-${role}-application-form] [data-prepare-${role}]`)!.click();
      await vi.waitFor(() => expect(root.querySelector(`[data-${role}-digest]`)?.textContent)
        .toMatch(/^Sign digest bytes: 0x[0-9a-f]{64}$/u));
      const signature = `0x${"d".repeat(192)}`;
      const submit = () => {
        const preparedForm = root.querySelector<HTMLFormElement>(`[data-${role}-application-form]`)!;
        preparedForm.querySelector<HTMLInputElement>("[name='memberSignature']")!.value = signature;
        preparedForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      };
      submit();
      await vi.waitFor(() => expect(root.textContent).toContain("different pending membership registry, scope, or applicant"));
      expect(submitted).toHaveLength(1);
      expect(root.textContent).not.toContain(`Pending ${role} application`);
      substitution = "registry";
      submit();
      await vi.waitFor(() => expect(submitted).toHaveLength(2));
      await vi.waitFor(() => expect(root.querySelector<HTMLButtonElement>(`[data-${role}-application-form] button[type='submit']`)?.disabled).toBe(false));
      expect(root.textContent).toContain("different pending membership registry, scope, or applicant");
      expect(root.textContent).not.toContain(`Pending ${role} application`);
      substitution = undefined;
      submit();
      await vi.waitFor(() => expect(root.textContent).toContain(`Pending ${role} application`));
      expect(submitted).toHaveLength(3);
      expect(submitted[2]?.intent).toMatchObject({ target: role, expectedEpochId: context.expectedEpochId });
      expect(submitted[2]?.signature.value).toBe(signature);
      expect(root.innerHTML).not.toContain(signature);
      const scope = submitted[2]!.scope as Parameters<typeof computeAuthorizationScopeCommitment>[0];
      expect(submitted[2]!.governedResource.id).toBe(role === "issuer"
        ? issuerGovernedResourceId(scope as Extract<typeof scope, { role: "issuer" }>, "credentialFamily")
        : role === "verifier" ? requestGovernedResourceId(scope as Extract<typeof scope, { role: "verifier" }>)
          : context.registryId);
    });
  }
});
