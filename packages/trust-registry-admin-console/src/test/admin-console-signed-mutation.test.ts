import { describe, expect, it, vi } from "vitest";

import {
  TrustRegistryApiSignedMutationRequestSchema,
  type TrustRegistryApiSignedMutationRequest,
} from "@midnight-ntwrk/trust-registry-api";
import { TrustRegistryAdminConsoleApiError, TrustRegistryAdminConsoleClient } from "../api.js";

const did = `did:midnight:undeployed:${"2".repeat(64)}`;
const hash = `0x${"a".repeat(64)}`;
const request = {
  intent: {
    version: "tr-mutation-intent-v1",
    registryId: "registry:test:trusted",
    actorDid: did,
    actorKeyId: `${did}#assertion-1`,
    actorRole: "maintainer",
    action: "approve",
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
  operation: { operation: "approve", target: "issuer", id: "auth:issuer:degree:v1" },
} satisfies TrustRegistryApiSignedMutationRequest;

describe("signed operator mutation transport", () => {
  it("fetches a no-cache context and forwards the signed envelope unchanged", async () => {
    expect(TrustRegistryApiSignedMutationRequestSchema.parse(request)).toEqual(request);
    const context = { registryId: "registry:test", expectedEpochId: "epoch:test", expectedWorkspaceCommitment: "0x01" };
    const result = { recordKind: "authorization", entry: { label: "degree" } };
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
      Response.json(init?.method === "POST" ? result : context)) as typeof fetch;
    const client = new TrustRegistryAdminConsoleClient("https://registry.example/", fetchImpl);

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

  it("surfaces invalid transition problems without hiding their status", async () => {
    const fetchImpl = vi.fn(async () => Response.json({
      status: 409, title: "invalid transition", detail: "Issuer is not proposed.",
    }, { status: 409 })) as typeof fetch;
    const client = new TrustRegistryAdminConsoleClient("https://registry.example", fetchImpl);
    await expect(client.submitSignedMutation(request)).rejects.toMatchObject({
      problem: { status: 409, title: "invalid transition" },
    } satisfies Partial<TrustRegistryAdminConsoleApiError>);
  });
});
