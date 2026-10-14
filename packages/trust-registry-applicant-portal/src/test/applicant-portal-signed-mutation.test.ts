import { describe, expect, it, vi } from "vitest";

import {
  TrustRegistryApiSignedMutationRequestSchema,
  type TrustRegistryApiSignedMutationRequest,
} from "@midnight-ntwrk/trust-registry-api";
import { TrustRegistryApplicantPortalApiError, TrustRegistryApplicantPortalClient } from "../api.js";

const did = `did:midnight:undeployed:${"1".repeat(64)}`;
const hash = `0x${"a".repeat(64)}`;
const request = {
  intent: {
    version: "tr-mutation-intent-v1",
    registryId: "registry:test:trusted",
    actorDid: did,
    actorKeyId: `${did}#assertion-1`,
    actorRole: "applicant",
    action: "submit",
    target: "issuer",
    targetId: "auth:issuer:degree:v1",
    scopeCommitment: hash,
    payloadCommitment: hash,
    nonce: hash,
    expectedWorkspaceCommitment: hash,
    expectedEpochId: "epoch:registry:test:trusted:seq-1",
    issuedAt: "2026-10-10T00:00:00.000Z",
    expiresAt: "2026-10-10T00:05:00.000Z",
  },
  signature: { keyId: `${did}#assertion-1`, algorithm: "jubjub-schnorr", value: `0x${"b".repeat(192)}` },
  operation: { operation: "submit", target: "issuer", label: "degree" },
} satisfies TrustRegistryApiSignedMutationRequest;

describe("signed applicant mutation transport", () => {
  it("loads a fresh context and submits only an externally signed envelope", async () => {
    expect(TrustRegistryApiSignedMutationRequestSchema.parse(request)).toEqual(request);
    const context = { registryId: "registry:test", expectedEpochId: "epoch:test", expectedWorkspaceCommitment: "0x01" };
    const result = { recordKind: "authorization", entry: { label: "degree" } };
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
      Response.json(init?.method === "POST" ? result : context)) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("https://registry.example/", fetchImpl);

    expect(await client.loadMutationContext()).toEqual(context);
    expect(await client.submitSignedMutation(request)).toEqual(result);
    expect(fetchImpl).toHaveBeenNthCalledWith(1,
      "https://registry.example/v1/registry/mutation-context", { cache: "no-store" });
    expect(fetchImpl).toHaveBeenNthCalledWith(2,
      "https://registry.example/v1/mutations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
  });

  it("preserves structured stale-workspace problems for retry with a new context", async () => {
    const fetchImpl = vi.fn(async () => Response.json({
      status: 409, title: "stale workspace", detail: "Refresh mutation context.",
    }, { status: 409 })) as typeof fetch;
    const client = new TrustRegistryApplicantPortalClient("https://registry.example", fetchImpl);
    await expect(client.submitSignedMutation(request)).rejects.toMatchObject({
      problem: { status: 409, title: "stale workspace" },
    } satisfies Partial<TrustRegistryApplicantPortalApiError>);
  });
});
