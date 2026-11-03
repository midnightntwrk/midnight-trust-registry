import { describe, expect, it, vi } from "vitest";

import { TrustRegistryAdminConsoleClient, type GovernedProposalRole } from "../api.js";

const hex = `0x${"11".repeat(32)}`;

describe("governed proposal client", () => {
  it("uses role-disjoint prepare, submit, and resolution paths without manufacturing signatures", async () => {
    const calls: { path: string; body: unknown }[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      calls.push({ path, body: JSON.parse(String(init?.body)) });
      if (path.endsWith("/prepare")) {
        const role = path.split("/")[3];
        return Response.json({
          registryId: hex,
          ...(role === "maintainer" ? { maintainerId: hex } : { authorizationId: hex }),
          policyCommitment: hex,
          policyVersion: "1",
          actionKind: hex,
          actionPayloadHash: hex,
          actionSequence: "2",
          evidenceHash: hex,
          ...(role === "issuer" ? { statusPolicyBindingCommitment: hex } : {}),
          evidenceVerifierAuthorizationId: hex,
          evidenceVerifierKeyIdCommitment: hex,
        });
      }
      if (path.endsWith("/submit")) return Response.json({ eventHash: hex }, { status: 202 });
      return Response.json({ state: "observed", eventHash: hex });
    });
    const client = new TrustRegistryAdminConsoleClient("http://127.0.0.1:4400", fetchImpl as typeof fetch);
    const evidence = { commitment: hex };
    const signers = [{ keyId: hex, publicKey: { x: "1", y: "2" }, signature: "0x0102" }];
    for (const role of ["issuer", "verifier", "auditor", "maintainer"] as const satisfies readonly GovernedProposalRole[]) {
      const prepared = await client.prepareProposal(role, `${role}:candidate`, evidence);
      expect(await client.submitProposal(role, `${role}:candidate`, {
        evidence, prepared, signers, evidenceVerifierSignature: "0x0304",
      })).toEqual({ eventHash: hex });
      expect(await client.resolveProposal(role, `${role}:candidate`, evidence)).toEqual({
        state: "observed", eventHash: hex,
      });
      expect(calls.slice(-3).map((call) => call.path)).toEqual([
        `/v1/governed/${role}/${role}%3Acandidate/proposal/prepare`,
        `/v1/governed/${role}/${role}%3Acandidate/proposal/submit`,
        `/v1/governed/${role}/${role}%3Acandidate/proposal/resolve`,
      ]);
      expect(calls.at(-2)?.body).toEqual({ evidence, prepared, signers, evidenceVerifierSignature: "0x0304" });
    }
  });
});
