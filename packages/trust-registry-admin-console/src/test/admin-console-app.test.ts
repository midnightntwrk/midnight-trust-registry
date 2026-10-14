// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";

import { createAdminConsoleApp } from "../app.js";

const counts = () => ({
  proposed: 0,
  authorized: 0,
  active: 0,
  suspended: 0,
  revoked: 0,
  superseded: 0,
  archived: 0,
});

const auditor = {
  label: "compliance",
  authorization: {
    authorizationId: "auth:auditor:compliance",
    registryId: "registry:local",
    role: "auditor",
    subjectDid: "did:midnight:testnet:auditor",
    resourceType: "request-profile",
    resourceId: `tr:request-resource:v1:${"a".repeat(64)}`,
    policyId: "policy:local",
    trustLevel: "approved",
    status: "active",
    proposedAt: "2026-10-08T00:00:00Z",
    activeFrom: "2026-10-08T01:00:00Z",
  },
  evidence: {
    epoch: { epochId: "epoch:1", stateRoot: "state-root" },
  },
};

describe("admin console browser handlers", () => {
  it("loads auditor cards and confirms actions and epoch publication before POST", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const confirm = vi.fn(() => false);
    const postedPaths: string[] = [];
    const postedBodies: (string | undefined)[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (init?.method === "POST") {
        postedPaths.push(path);
        postedBodies.push(init.body?.toString());
        return Response.json({
          recordKind: "epoch",
          epoch: { epochId: "epoch:2" },
        });
      }
      if (path === "/v1/registry/summary") {
        return Response.json({
          issuerCounts: counts(),
          verifierCounts: counts(),
          auditorCounts: { ...counts(), active: 1 },
          recognitionCounts: counts(),
          currentEpochId: "epoch:1",
          registryLabel: "local",
          registryId: "registry:local",
          registryDid: "did:midnight:testnet:registry",
          policyId: "policy:local",
          epochCount: 1,
        });
      }
      return Response.json({ entries: path === "/v1/authorizations/auditor" ? [auditor] : [] });
    });
    createAdminConsoleApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400"),
      storage: window.localStorage,
      fetchImpl: fetchImpl as typeof fetch,
      confirm,
    });

    await vi.waitFor(() => expect(root.textContent).toContain(auditor.authorization.resourceId));
    root.querySelector<HTMLButtonElement>("[data-action='suspend']")!.click();
    await vi.waitFor(() => expect(confirm).toHaveBeenCalledWith(
      expect.stringContaining("auditor record auth:auditor:compliance"),
    ));
    await vi.waitFor(() => expect(root.querySelector("[data-action='suspend']")?.hasAttribute("disabled")).toBe(false));
    expect(postedPaths).toEqual([]);

    const labelInput = root.querySelector<HTMLInputElement>("[data-epoch-label]")!;
    labelInput.value = "audit-round";
    labelInput.dispatchEvent(new Event("input", { bubbles: true }));
    root.querySelector<HTMLFormElement>("[data-epoch-form]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    expect(root.querySelector("[data-epoch-form] button")?.hasAttribute("disabled")).toBe(true);
    expect(root.querySelector("[data-action='suspend']")?.hasAttribute("disabled")).toBe(true);
    await vi.waitFor(() => expect(confirm).toHaveBeenCalledWith(
      expect.stringContaining("anchors the current state root"),
    ));
    await vi.waitFor(() => expect(root.querySelector("[data-epoch-form] button")?.hasAttribute("disabled")).toBe(false));
    expect(postedPaths).toEqual([]);
    expect(root.querySelector<HTMLInputElement>("[data-epoch-label]")?.value).toBe("audit-round");

    confirm.mockReturnValue(true);
    root.querySelector<HTMLFormElement>("[data-epoch-form]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(postedPaths).toEqual(["/v1/epochs/publish"]));
    expect(postedBodies).toEqual([JSON.stringify({ label: "audit-round" })]);
    await vi.waitFor(() => expect(root.querySelector<HTMLInputElement>("[data-epoch-label]")?.value).toBe(""));
  });

  it("prepares and submits external quorum signatures without using fixture mutation routes", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    const confirm = vi.fn(() => false);
    const prepared = {
      registryId: `0x${"01".repeat(32)}`,
      authorizationId: `0x${"02".repeat(32)}`,
      policyCommitment: `0x${"03".repeat(32)}`,
      actionKind: `0x${"04".repeat(32)}`,
      actionPayloadHash: `0x${"05".repeat(32)}`,
      actionSequence: "7",
      previousLifecycleEventHash: `0x${"06".repeat(32)}`,
      evidenceHash: `0x${"07".repeat(32)}`,
    };
    const signers = [{
      keyId: `0x${"08".repeat(32)}`,
      publicKey: { x: "1", y: "2" },
      signature: "0x0102",
    }];
    const posted: { path: string; body: string | undefined }[] = [];
    let status: "proposed" | "authorized" | "active" | "suspended" | "revoked" = "proposed";
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path.startsWith("/v1/governed/")) {
        if (init?.method === "POST") {
          posted.push({ path, body: init.body?.toString() });
          status = path.endsWith("/approve") ? "authorized"
            : path.endsWith("/activate") ? "active"
              : path.endsWith("/suspend") ? "suspended" : "revoked";
          return Response.json({ eventHash: `0x${"09".repeat(32)}` }, { status: 202 });
        }
        return Response.json(prepared);
      }
      if (path === "/v1/registry/summary") {
        return Response.json({
          issuerCounts: counts(), verifierCounts: counts(),
          auditorCounts: { ...counts(), [status]: 1 }, recognitionCounts: counts(),
          currentEpochId: "epoch:1", registryLabel: "local", registryId: "registry:local",
          registryDid: "did:midnight:testnet:registry", policyId: "policy:local", epochCount: 1,
        });
      }
      return Response.json({
        entries: path === "/v1/authorizations/auditor"
          ? [{ ...auditor, authorization: { ...auditor.authorization, status } }]
          : [],
      });
    });
    createAdminConsoleApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400"),
      storage: window.localStorage,
      fetchImpl: fetchImpl as typeof fetch,
      confirm,
    });

    await vi.waitFor(() => expect(root.querySelector("[data-governed-prepare]")).not.toBeNull());
    root.querySelector<HTMLButtonElement>("[data-governed-prepare]")!.click();
    await vi.waitFor(() => expect(root.querySelector("[data-governed-submit]")).not.toBeNull());
    expect(root.textContent).toContain(prepared.policyCommitment);
    const signerInput = root.querySelector<HTMLTextAreaElement>("[data-governed-signers]")!;
    signerInput.value = "not json";
    signerInput.dispatchEvent(new Event("input", { bubbles: true }));
    root.querySelector<HTMLFormElement>("[data-governed-submit]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(root.textContent).toContain("Signer input must be a JSON array"));
    expect(posted).toEqual([]);

    const correctedInput = root.querySelector<HTMLTextAreaElement>("[data-governed-signers]")!;
    correctedInput.value = JSON.stringify(signers);
    correctedInput.dispatchEvent(new Event("input", { bubbles: true }));
    root.querySelector<HTMLFormElement>("[data-governed-submit]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(confirm).toHaveBeenCalledWith(
      expect.stringContaining("external signatures to approve auditor"),
    ));
    expect(posted).toEqual([]);

    confirm.mockReturnValue(true);
    root.querySelector<HTMLFormElement>("[data-governed-submit]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]?.path).toBe("/v1/governed/auditor/auth%3Aauditor%3Acompliance/actions/approve");
    expect(JSON.parse(posted[0]!.body!)).toEqual({ prepared, signers });
    await vi.waitFor(() => expect(root.textContent).toContain("Compact approve accepted"));
    expect(root.querySelector("[data-governed-prepare]")?.textContent).toContain("activate");
    for (const [action, nextAction] of [
      ["activate", "suspend"], ["suspend", "revoke"], ["revoke", null],
    ] as const) {
      root.querySelector<HTMLButtonElement>("[data-governed-prepare]")!.click();
      await vi.waitFor(() => expect(root.querySelector("[data-governed-submit]")).not.toBeNull());
      const input = root.querySelector<HTMLTextAreaElement>("[data-governed-signers]")!;
      input.value = JSON.stringify(signers);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      root.querySelector<HTMLFormElement>("[data-governed-submit]")!.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
      await vi.waitFor(() => expect(posted.at(-1)?.path).toBe(
        `/v1/governed/auditor/auth%3Aauditor%3Acompliance/actions/${action}`,
      ));
      if (nextAction === null) {
        await vi.waitFor(() => expect(root.querySelector("[data-governed-prepare]")).toBeNull());
      } else {
        await vi.waitFor(() => expect(root.querySelector("[data-governed-prepare]")?.textContent)
          .toContain(nextAction));
      }
    }
    expect(posted.every((request) => !request.path.startsWith("/v1/applications/"))).toBe(true);
  });

  it("prepares a redacted issuer proposal and invalidates stale evidence before external signing", async () => {
    const root = document.createElement("div");
    document.body.replaceChildren(root);
    window.localStorage.clear();
    const prepared = {
      registryId: `0x${"01".repeat(32)}`,
      authorizationId: `0x${"02".repeat(32)}`,
      policyCommitment: `0x${"03".repeat(32)}`,
      policyVersion: "1",
      actionKind: `0x${"04".repeat(32)}`,
      actionPayloadHash: `0x${"05".repeat(32)}`,
      actionSequence: "7",
      evidenceHash: `0x${"06".repeat(32)}`,
      statusPolicyBindingCommitment: `0x${"07".repeat(32)}`,
      evidenceVerifierAuthorizationId: `0x${"08".repeat(32)}`,
      evidenceVerifierKeyIdCommitment: `0x${"09".repeat(32)}`,
    };
    const evidence = {
      envelope: {
        version: "tr-application-evidence-v1", registryId: "registry:local", applicationId: "application:issuer:alice",
        subjectDid: "did:midnight:testnet:alice", role: "issuer", policyId: "policy:local", policyVersion: "1",
        scopeCommitment: `0x${"aa".repeat(32)}`, governedResource: { type: "schema", id: "schema:alice" },
        evidenceVerifierDid: "did:midnight:testnet:verifier", verifiedAt: "2026-10-13T00:00:00Z",
        expiresAt: "2026-10-13T01:00:00Z", challengeHash: `0x${"bb".repeat(32)}`,
        presentationHash: `0x${"cc".repeat(32)}`, claimsCommitment: `0x${"dd".repeat(32)}`,
      },
      commitment: `0x${"ee".repeat(32)}`,
      signature: { keyId: "did:midnight:testnet:verifier#assertion-1", algorithm: "jubjub-schnorr", value: "0x0102" },
    };
    const signers = [{ keyId: `0x${"0a".repeat(32)}`, publicKey: { x: "1", y: "2" }, signature: "0x0102" }];
    const verifierSignature = "0x0304";
    const posted: { path: string; body: unknown }[] = [];
    let available = false;
    let observed = false;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/proposal/prepare")) {
        posted.push({ path, body: JSON.parse(String(init?.body)) });
        return available
          ? Response.json(prepared)
          : Response.json({ status: 503, title: "governed proposal unavailable" }, { status: 503 });
      }
      if (path.endsWith("/proposal/submit")) {
        posted.push({ path, body: JSON.parse(String(init?.body)) });
        return Response.json({ eventHash: `0x${"0b".repeat(32)}` }, { status: 202 });
      }
      if (path.endsWith("/proposal/resolve")) {
        posted.push({ path, body: JSON.parse(String(init?.body)) });
        return Response.json(observed
          ? { state: "observed", eventHash: `0x${"0b".repeat(32)}` }
          : { state: "not-observed" });
      }
      if (path === "/v1/registry/summary") {
        return Response.json({
          issuerCounts: counts(), verifierCounts: counts(), auditorCounts: counts(), recognitionCounts: counts(),
          currentEpochId: "epoch:1", registryLabel: "local", registryId: "registry:local",
          registryDid: "did:midnight:testnet:registry", policyId: "policy:local", epochCount: 1,
        });
      }
      return Response.json({ entries: [] });
    });
    createAdminConsoleApp(root, {
      initialUrl: new URL("http://127.0.0.1:4173/?apiBase=http://127.0.0.1:4400"),
      storage: window.localStorage,
      fetchImpl: fetchImpl as typeof fetch,
      confirm: () => true,
    });
    await vi.waitFor(() => expect(root.querySelector("[data-proposal-prepare] button")?.hasAttribute("disabled")).toBe(false));

    const setInput = (selector: string, value: string) => {
      const input = root.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
      input.value = value;
      input.dispatchEvent(new Event("input", { bubbles: true }));
    };
    const prepare = () => root.querySelector<HTMLFormElement>("[data-proposal-prepare]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );

    setInput("[data-proposal-id]", "issuer:alice");
    setInput("[data-proposal-evidence]", JSON.stringify({ ...evidence, verifiablePresentation: { secret: "private" } }));
    prepare();
    await vi.waitFor(() => expect(root.textContent).toContain("without raw VC/VP fields"));
    expect(posted).toEqual([]);
    setInput("[data-proposal-evidence]", JSON.stringify({
      ...evidence,
      envelope: { ...evidence.envelope, claimsCommitment: { secret: "private" } },
    }));
    prepare();
    await vi.waitFor(() => expect(root.textContent).toContain("without raw VC/VP fields"));
    expect(posted).toEqual([]);
    setInput("[data-proposal-evidence]", JSON.stringify(evidence));
    prepare();
    await vi.waitFor(() => expect(root.textContent).toContain("governed proposal unavailable"));
    expect(root.querySelector("[data-proposal-submit]")).toBeNull();

    available = true;
    prepare();
    await vi.waitFor(() => expect(root.querySelector("[data-proposal-submit]")).not.toBeNull());
    expect(root.textContent).toContain(prepared.policyCommitment);
    const changedEvidence = {
      ...evidence,
      envelope: { ...evidence.envelope, presentationHash: `0x${"ff".repeat(32)}` },
    };
    setInput("[data-proposal-evidence]", JSON.stringify(changedEvidence));
    expect(root.querySelector("[data-proposal-submit]")).toBeNull();
    prepare();
    await vi.waitFor(() => expect(root.querySelector("[data-proposal-submit]")).not.toBeNull());

    setInput("[data-proposal-signers]", JSON.stringify([{ ...signers[0], privateKey: "must-not-leave-browser" }]));
    setInput("[data-proposal-verifier-signature]", verifierSignature);
    root.querySelector<HTMLFormElement>("[data-proposal-submit]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(root.textContent).toContain("External signer must contain only"));
    expect(posted.every((request) => !request.path.endsWith("/proposal/submit"))).toBe(true);
    setInput("[data-proposal-signers]", JSON.stringify(signers));
    setInput("[data-proposal-verifier-signature]", verifierSignature);
    root.querySelector<HTMLFormElement>("[data-proposal-submit]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(posted.at(-1)?.path).toBe("/v1/governed/issuer/issuer%3Aalice/proposal/submit"));
    expect(posted.at(-1)?.body).toEqual({
      evidence: changedEvidence, prepared, signers, evidenceVerifierSignature: verifierSignature,
    });
    await vi.waitFor(() => expect(root.textContent).toContain("Compact issuer proposal accepted"));
    expect(window.localStorage.getItem("trust-registry.admin.api-base")).toBeNull();
    expect(window.localStorage.length).toBe(0);
    expect(root.querySelector("[data-proposal-submit]")).toBeNull();

    const selectRole = (role: string) => {
      const selector = root.querySelector<HTMLSelectElement>("[data-proposal-role]")!;
      selector.value = role;
      selector.dispatchEvent(new Event("change", { bubbles: true }));
    };
    expect(Array.from(root.querySelector<HTMLSelectElement>("[data-proposal-role]")!.options)
      .map((option) => option.value)).toEqual(["issuer", "verifier", "auditor", "maintainer"]);
    selectRole("verifier");
    setInput("[data-proposal-id]", "verifier:bob");
    setInput("[data-proposal-evidence]", JSON.stringify(evidence));
    prepare();
    await vi.waitFor(() => expect(root.textContent).toContain("evidence role must match"));
    expect(posted.filter((request) => request.path.endsWith("/proposal/prepare"))).toHaveLength(3);

    const verifierEvidence = { ...evidence, envelope: { ...evidence.envelope, role: "verifier" } };
    setInput("[data-proposal-evidence]", JSON.stringify(verifierEvidence));
    root.querySelector<HTMLButtonElement>("[data-proposal-resolve]")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain("do not resubmit automatically"));
    expect(posted.at(-1)?.path).toBe("/v1/governed/verifier/verifier%3Abob/proposal/resolve");
    expect(posted.at(-1)?.body).toEqual({ evidence: verifierEvidence });
    observed = true;
    root.querySelector<HTMLButtonElement>("[data-proposal-resolve]")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain("Compact verifier proposal observed"));

    prepare();
    await vi.waitFor(() => expect(root.querySelector("[data-proposal-submit]")).not.toBeNull());
    selectRole("auditor");
    expect(root.querySelector("[data-proposal-submit]")).toBeNull();
    selectRole("verifier");
    prepare();
    await vi.waitFor(() => expect(root.querySelector("[data-proposal-submit]")).not.toBeNull());
    setInput("[data-proposal-signers]", JSON.stringify(signers));
    setInput("[data-proposal-verifier-signature]", verifierSignature);
    root.querySelector<HTMLFormElement>("[data-proposal-submit]")!.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => expect(posted.at(-1)?.path).toBe("/v1/governed/verifier/verifier%3Abob/proposal/submit"));
    await vi.waitFor(() => expect(root.textContent).toContain("Compact verifier proposal accepted"));
  });
});
