import { Buffer } from "node:buffer";
import { fork, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createOperatorWorkspace,
  applyWorkspaceOperation,
  MAX_CONSUMED_MUTATION_NONCES,
  MAX_CONSUMED_MUTATION_NONCES_PER_ACTOR,
  loadWorkspaceFromFile,
  resolveWorkspaceOperationRecord,
  writeWorkspaceToFile,
  type TrustRegistryOperatorWorkspace,
  type TrustRegistryOperatorWorkspaceOperation,
} from "@midnight-ntwrk/trust-registry-cli";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  computeAuthorizationScopeCommitment,
  computeMutationPayloadCommitment,
  computeRecognitionMutationScopeCommitment,
  mutationIntentDigestBytes,
  sha256Hex,
  type MutationIntent,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createIssuerScenarioFixture,
  createVerifierScenarioFixture,
  createAuditorScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createAuditorAuthorizationScopeFixture,
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "@midnight-ntwrk/trust-registry-integration";
import { afterEach, describe, expect, it } from "vitest";

import { createTrustRegistryApiServer } from "../server.js";
import type { GovernedRecognitionProposalPort } from "../governed-recognition-proposals.js";
import { createWorkspaceFileSource } from "../source.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const now = "2026-10-10T00:01:00.000Z";
const applicantSeed = new Uint8Array(32).fill(47);
const maintainerSeed = new Uint8Array(32).fill(61);
const fixture = createIssuerScenarioFixture("signed-http");
const wrongApplicantDid = createMidnightDid("signed-http:wrong-applicant");

const signatureFor = (intent: MutationIntent, seed: Uint8Array) => ({
  keyId: intent.actorKeyId,
  algorithm: "jubjub-schnorr" as const,
  value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
    seed, mutationIntentDigestBytes(intent),
  ))).toString("hex")}`,
});

const operationPayload = (operation: TrustRegistryOperatorWorkspaceOperation) =>
  operation.operation === "publish-epoch"
    ? operation.label === undefined ? {} : { label: operation.label }
    : operation.operation === "submit"
      ? { target: operation.target, label: operation.label }
      : { target: operation.target, id: operation.id };

const buildIntent = (
  workspace: TrustRegistryOperatorWorkspace,
  operation: TrustRegistryOperatorWorkspaceOperation,
  actorDid: string,
  actorRole: "applicant" | "maintainer",
  nonceByte: string,
  record: { targetId: string; scopeCommitment: string } = {
    targetId: fixture.authorizationId,
    scopeCommitment: computeAuthorizationScopeCommitment(fixture.authorizationScope),
  },
): MutationIntent => ({
  version: "tr-mutation-intent-v1",
  registryId: workspace.snapshot.registry.registryId,
  actorDid,
  actorKeyId: `${actorDid}#assertion-1`,
  actorRole,
  action: operation.operation,
  target: operation.operation === "publish-epoch" ? "epoch" : operation.target,
  targetId: operation.operation === "publish-epoch"
    ? workspace.snapshot.currentEpoch.epochId
    : operation.operation === "submit" ? record.targetId : operation.id,
  scopeCommitment: operation.operation === "publish-epoch"
    ? computeAuthorizationScopeCommitment({
      version: "tr-scope-v1", role: "maintainer", registryId: workspace.snapshot.registry.registryId,
    })
    : record.scopeCommitment,
  payloadCommitment: computeMutationPayloadCommitment(operationPayload(operation)),
  nonce: `0x${nonceByte.repeat(32)}`,
  expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
  expectedEpochId: workspace.snapshot.currentEpoch.epochId,
  issuedAt: "2026-10-10T00:00:00.000Z",
  expiresAt: "2026-10-10T00:05:00.000Z",
});

const listen = async (server: Server): Promise<string> => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address expected");
  return `http://127.0.0.1:${address.port.toString()}`;
};

const close = async (server: Server): Promise<void> => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
};

const holdWorkspaceLockInChild = async (workspacePath: string): Promise<{
  child: ChildProcess;
  release: () => Promise<void>;
}> => {
  const child = fork(
    fileURLToPath(new URL("./fixtures/hold-workspace-lock.mjs", import.meta.url)),
    [workspacePath],
    { stdio: ["ignore", "ignore", "pipe", "ipc"] },
  );
  let diagnostic = "";
  child.stderr?.on("data", (chunk: Buffer) => { diagnostic += chunk.toString(); });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`Child did not acquire workspace lock: ${diagnostic}`));
    }, 10_000);
    const cleanup = () => {
      clearTimeout(timer);
      child.off("message", onMessage);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    const onMessage = (message: unknown) => {
      if (message !== "locked") return;
      cleanup();
      resolve();
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onExit = (code: number | null) => {
      cleanup();
      reject(new Error(`Child exited before acquiring workspace lock (${String(code)}): ${diagnostic}`));
    };
    child.on("message", onMessage);
    child.once("error", onError);
    child.once("exit", onExit);
  });
  return {
    child,
    release: () => new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error(`Lock holder did not exit after release: ${diagnostic}`));
      }, 5000);
      child.once("error", (error) => { clearTimeout(timer); reject(error); });
      child.once("exit", (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error(`Lock holder failed: ${diagnostic}`));
      });
      child.send("release");
    }),
  };
};

describe("DID-signed HTTP mutation journey", () => {
  let tempDir: string | undefined;
  let server: Server | undefined;
  let lockHolder: ChildProcess | undefined;

  afterEach(async () => {
    if (lockHolder !== undefined && lockHolder.exitCode === null) lockHolder.kill();
    if (server !== undefined) await close(server);
    if (tempDir !== undefined) await rm(tempDir, { force: true, recursive: true });
    server = undefined;
    tempDir = undefined;
  });

  it("moves an issuer application to an epoch while refusing unsigned, replayed, and substituted writes", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tr-signed-http-"));
    const workspacePath = join(tempDir, "workspace.json");
    const initial = createOperatorWorkspace({ label: "signed-http-registry" });
    await writeWorkspaceToFile(workspacePath, initial);
    const maintainerDid = initial.snapshot.registry.maintainerDids[0];
    if (maintainerDid === undefined) throw new Error("maintainer fixture missing");
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(fixture.subjectDid, {
        verificationMethodId: "assertion-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
      }),
      createMidnightDidLedgerFixture(wrongApplicantDid, {
        verificationMethodId: "assertion-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
      }),
      createMidnightDidLedgerFixture(maintainerDid, {
        verificationMethodId: "assertion-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(maintainerSeed),
        capabilityInvocation: true,
      }),
    ]);
    const start = async () => {
      server = createTrustRegistryApiServer({
        source: createWorkspaceFileSource(workspacePath),
        clock: () => now,
        mutationDidResolver: resolver,
      });
      return listen(server);
    };
    let url = await start();
    const post = async (body: unknown, path = "/v1/mutations") => fetch(`${url}${path}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    const submit = { operation: "submit", target: "issuer", label: "signed-http" } as const;
    const applicantIntent = buildIntent(initial, submit, fixture.subjectDid, "applicant", "33");
    const signedSubmit = { intent: applicantIntent, signature: signatureFor(applicantIntent, applicantSeed), operation: submit };

    expect((await post({ target: "issuer", label: "unsigned" }, "/v1/applications")).status).toBe(403);
    expect((await loadWorkspaceFromFile(workspacePath)).operations).toHaveLength(0);
    const wrongSignature = await post({ ...signedSubmit, signature: {
      ...signedSubmit.signature, value: `0x${"00".repeat(96)}`,
    } });
    expect(wrongSignature.status).toBe(401);
    expect((await loadWorkspaceFromFile(workspacePath)).operations).toHaveLength(0);
    const wrongActorIntent = buildIntent(initial, submit, wrongApplicantDid, "applicant", "34");
    expect((await post({ intent: wrongActorIntent, signature: signatureFor(wrongActorIntent, applicantSeed), operation: submit })).status).toBe(403);
    expect((await loadWorkspaceFromFile(workspacePath)).operations).toHaveLength(0);
    const wrongScopeIntent = { ...applicantIntent, scopeCommitment: `0x${"aa".repeat(32)}`, nonce: `0x${"35".repeat(32)}` };
    expect((await post({ intent: wrongScopeIntent, signature: signatureFor(wrongScopeIntent, applicantSeed), operation: submit })).status).toBe(403);
    expect((await loadWorkspaceFromFile(workspacePath)).operations).toHaveLength(0);

    const holder = await holdWorkspaceLockInChild(workspacePath);
    lockHolder = holder.child;
    const lockedResponse = await post(signedSubmit);
    expect(lockedResponse.status).toBe(409);
    expect((await lockedResponse.json()).type).toMatch(/workspace-locked/u);
    expect((await loadWorkspaceFromFile(workspacePath)).operations).toHaveLength(0);
    await holder.release();
    lockHolder = undefined;

    const concurrent = await Promise.all([post(signedSubmit), post(signedSubmit)]);
    expect(concurrent.map((response) => response.status).sort()).toEqual([201, 409]);
    if (server !== undefined) await close(server);
    server = undefined;
    url = await start();
    expect((await post(signedSubmit)).status).toBe(409);
    const afterSubmit = await loadWorkspaceFromFile(workspacePath);
    expect(afterSubmit.operations).toHaveLength(1);
    expect(Object.keys(afterSubmit.consumedMutationNonces)).toHaveLength(1);
    const staleIntent = { ...applicantIntent, nonce: `0x${"36".repeat(32)}` };
    expect((await post({ intent: staleIntent, signature: signatureFor(staleIntent, applicantSeed), operation: submit })).status).toBe(409);

    for (const [index, action] of (["approve", "activate"] as const).entries()) {
      const current = await loadWorkspaceFromFile(workspacePath);
      const operation = { operation: action, target: "issuer", id: fixture.authorizationId } as const;
      const intent = buildIntent(current, operation, maintainerDid, "maintainer", index === 0 ? "37" : "38");
      expect((await post({ intent, signature: signatureFor(intent, maintainerSeed), operation })).status).toBe(200);
    }
    const active = await fetch(`${url}/v1/authorizations/issuer/${fixture.authorizationId}`);
    expect(active.status).toBe(200);
    expect((await active.json()).authorization.status).toBe("active");
    const beforePublish = await loadWorkspaceFromFile(workspacePath);
    const publish = { operation: "publish-epoch", label: "signed-http-epoch" } as const;
    const publishIntent = buildIntent(beforePublish, publish, maintainerDid, "maintainer", "39");
    expect((await post({ intent: publishIntent, signature: signatureFor(publishIntent, maintainerSeed), operation: publish })).status).toBe(200);
    const afterPublish = await loadWorkspaceFromFile(workspacePath);
    expect(afterPublish.operations).toHaveLength(4);
    expect(Object.keys(afterPublish.consumedMutationNonces)).toHaveLength(4);
    expect(afterPublish.snapshot.currentEpoch.epochId).not.toBe(initial.snapshot.currentEpoch.epochId);
  }, 60_000);

  it("rejects an intent that expires during DID resolution without consuming its nonce", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tr-signed-expiry-"));
    const workspacePath = join(tempDir, "workspace.json");
    const workspace = createOperatorWorkspace({ label: "signed-expiry" });
    await writeWorkspaceToFile(workspacePath, workspace);
    const baseResolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(fixture.subjectDid, {
        verificationMethodId: "assertion-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
      }),
    ]);
    let clockTime = "2026-10-10T00:04:59.999Z";
    let advanceOnResolve = true;
    const resolver = {
      resolveResult: async (did: Parameters<typeof baseResolver.resolveResult>[0]) => {
        const result = await baseResolver.resolveResult(did);
        if (advanceOnResolve) {
          clockTime = "2026-10-10T00:05:00.000Z";
          advanceOnResolve = false;
        }
        return result;
      },
    };
    server = createTrustRegistryApiServer({
      source: createWorkspaceFileSource(workspacePath),
      clock: () => clockTime,
      mutationDidResolver: resolver,
    });
    const url = await listen(server);
    const operation = { operation: "submit", target: "issuer", label: "signed-http" } as const;
    const intent = buildIntent(workspace, operation, fixture.subjectDid, "applicant", "7a");
    const body = { intent, signature: signatureFor(intent, applicantSeed), operation };
    const post = () => fetch(`${url}/v1/mutations`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    expect((await post()).status).toBe(403);
    const unchanged = await loadWorkspaceFromFile(workspacePath);
    expect(unchanged.operations).toHaveLength(0);
    expect(Object.keys(unchanged.consumedMutationNonces)).toHaveLength(0);
    clockTime = "2026-10-10T00:04:59.999Z";
    expect((await post()).status).toBe(201);
    expect(Object.keys((await loadWorkspaceFromFile(workspacePath)).consumedMutationNonces)).toHaveLength(1);
  }, 20_000);

  it("persists expiry pruning under the same signed workspace mutation", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tr-signed-pruning-"));
    const workspacePath = join(tempDir, "workspace.json");
    const expiredKey = sha256Hex("expired-signed-intent");
    const initial = {
      ...createOperatorWorkspace({ label: "signed-pruning" }),
      consumedMutationNonces: { [expiredKey]: {
        actorKey: sha256Hex("expired-actor"), expiresAt: "2026-10-10T00:00:59.999Z",
      } },
    };
    await writeWorkspaceToFile(workspacePath, initial);
    const resolver = createMidnightDidResolver([createMidnightDidLedgerFixture(fixture.subjectDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
    })]);
    server = createTrustRegistryApiServer({
      source: createWorkspaceFileSource(workspacePath), clock: () => now, mutationDidResolver: resolver,
    });
    const url = await listen(server);
    const operation = { operation: "submit", target: "issuer", label: "signed-http" } as const;
    const intent = buildIntent(initial, operation, fixture.subjectDid, "applicant", "60");
    const response = await fetch(`${url}/v1/mutations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent, signature: signatureFor(intent, applicantSeed), operation }),
    });
    expect(response.status).toBe(201);
    const stored = await loadWorkspaceFromFile(workspacePath);
    expect(stored.consumedMutationNonces[expiredKey]).toBeUndefined();
    expect(Object.keys(stored.consumedMutationNonces)).toHaveLength(1);
  }, 20_000);

  it("returns a fail-closed problem when every retained nonce is still live", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tr-signed-capacity-"));
    const workspacePath = join(tempDir, "workspace.json");
    const initial = {
      ...createOperatorWorkspace({ label: "signed-capacity" }),
      consumedMutationNonces: Object.fromEntries(
        Array.from({ length: MAX_CONSUMED_MUTATION_NONCES }, (_, index) => [
          `0x${index.toString(16).padStart(64, "0")}`,
          { actorKey: sha256Hex(`actor:${index}`), expiresAt: "2026-10-10T00:05:00.000Z" },
        ]),
      ),
    };
    await writeWorkspaceToFile(workspacePath, initial);
    const resolver = createMidnightDidResolver([createMidnightDidLedgerFixture(fixture.subjectDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
    })]);
    server = createTrustRegistryApiServer({
      source: createWorkspaceFileSource(workspacePath), clock: () => now, mutationDidResolver: resolver,
    });
    const url = await listen(server);
    const operation = { operation: "submit", target: "issuer", label: "signed-http" } as const;
    const intent = buildIntent(initial, operation, fixture.subjectDid, "applicant", "61");
    const response = await fetch(`${url}/v1/mutations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent, signature: signatureFor(intent, applicantSeed), operation }),
    });
    expect(response.status).toBe(503);
    expect((await response.json()).type).toMatch(/mutation-nonce-capacity/u);
    const stored = await loadWorkspaceFromFile(workspacePath);
    expect(stored.operations).toHaveLength(0);
    expect(Object.keys(stored.consumedMutationNonces)).toHaveLength(MAX_CONSUMED_MUTATION_NONCES);
  }, 20_000);

  it("returns an actor-scoped capacity problem before one caller can exhaust the global window", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tr-signed-actor-capacity-"));
    const workspacePath = join(tempDir, "workspace.json");
    const initialWorkspace = createOperatorWorkspace({ label: "signed-actor-capacity" });
    const actorKey = sha256Hex(JSON.stringify([
      "tr:mutation:actor:v1", initialWorkspace.snapshot.registry.registryId, fixture.subjectDid,
    ]));
    const initial = {
      ...initialWorkspace,
      consumedMutationNonces: Object.fromEntries(Array.from(
        { length: MAX_CONSUMED_MUTATION_NONCES_PER_ACTOR }, (_, index) => [
          `0x${index.toString(16).padStart(64, "0")}`,
          { actorKey, expiresAt: "2026-10-10T00:05:00.000Z" },
        ],
      )),
    };
    await writeWorkspaceToFile(workspacePath, initial);
    const resolver = createMidnightDidResolver([createMidnightDidLedgerFixture(fixture.subjectDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
    })]);
    server = createTrustRegistryApiServer({
      source: createWorkspaceFileSource(workspacePath), clock: () => now, mutationDidResolver: resolver,
    });
    const url = await listen(server);
    const operation = { operation: "submit", target: "issuer", label: "signed-http" } as const;
    const intent = buildIntent(initial, operation, fixture.subjectDid, "applicant", "62");
    const response = await fetch(`${url}/v1/mutations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent, signature: signatureFor(intent, applicantSeed), operation }),
    });
    expect(response.status).toBe(429);
    expect((await response.json()).type).toMatch(/mutation-actor-nonce-capacity/u);
    const stored = await loadWorkspaceFromFile(workspacePath);
    expect(stored.operations).toHaveLength(0);
    expect(Object.keys(stored.consumedMutationNonces)).toHaveLength(MAX_CONSUMED_MUTATION_NONCES_PER_ACTOR);

    const unrelatedEntries = Object.fromEntries(Object.entries(initial.consumedMutationNonces)
      .map(([key, entry]) => [key, { ...entry, actorKey: sha256Hex("unrelated-actor") }]));
    const unrelatedWorkspace = { ...initial, consumedMutationNonces: unrelatedEntries };
    await writeWorkspaceToFile(workspacePath, unrelatedWorkspace);
    const crossActorIntent = buildIntent(unrelatedWorkspace, operation, fixture.subjectDid, "applicant", "63");
    const crossActorResponse = await fetch(`${url}/v1/mutations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intent: crossActorIntent, signature: signatureFor(crossActorIntent, applicantSeed), operation,
      }),
    });
    expect(crossActorResponse.status).toBe(201);
    expect(Object.keys((await loadWorkspaceFromFile(workspacePath)).consumedMutationNonces))
      .toHaveLength(MAX_CONSUMED_MUTATION_NONCES_PER_ACTOR + 1);
  }, 20_000);

  it("rejects backward clock movement without pruning or consuming a nonce", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tr-signed-clock-"));
    const workspacePath = join(tempDir, "workspace.json");
    const highWater = "2026-10-10T00:01:30.000Z";
    const initial = {
      ...createOperatorWorkspace({ label: "signed-clock" }), mutationNonceClock: highWater,
    };
    await writeWorkspaceToFile(workspacePath, initial);
    const resolver = createMidnightDidResolver([createMidnightDidLedgerFixture(fixture.subjectDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
    })]);
    let clockTime = now;
    server = createTrustRegistryApiServer({
      source: createWorkspaceFileSource(workspacePath), clock: () => clockTime, mutationDidResolver: resolver,
    });
    const url = await listen(server);
    const operation = { operation: "submit", target: "issuer", label: "signed-http" } as const;
    const intent = buildIntent(initial, operation, fixture.subjectDid, "applicant", "64");
    const post = () => fetch(`${url}/v1/mutations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ intent, signature: signatureFor(intent, applicantSeed), operation }),
    });
    const rejected = await post();
    expect(rejected.status).toBe(503);
    expect((await rejected.json()).type).toMatch(/mutation-nonce-clock-rollback/u);
    expect((await loadWorkspaceFromFile(workspacePath)).operations).toHaveLength(0);
    clockTime = highWater;
    expect((await post()).status).toBe(201);
  }, 20_000);

  it("accepts exact verifier, auditor, and recognition scopes without promoting recognition to membership", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tr-signed-roles-"));
    const workspacePath = join(tempDir, "workspace.json");
    const initial = createOperatorWorkspace({ label: "signed-role-registry" });
    await writeWorkspaceToFile(workspacePath, initial);
    const verifier = createVerifierScenarioFixture("signed-verifier");
    const auditor = createAuditorScenarioFixture("signed-auditor");
    const recognition = createRecognitionScenarioFixture("signed-recognition");
    const maintainerDid = initial.snapshot.registry.maintainerDids[0];
    if (maintainerDid === undefined) throw new Error("maintainer fixture missing");
    const resolver = createMidnightDidResolver([
      ...[verifier.subjectDid, auditor.subjectDid].map((did) => createMidnightDidLedgerFixture(did, {
        verificationMethodId: "assertion-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
      })),
      createMidnightDidLedgerFixture(maintainerDid, {
        verificationMethodId: "assertion-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(maintainerSeed),
        capabilityInvocation: true,
      }),
    ]);
    server = createTrustRegistryApiServer({
      source: createWorkspaceFileSource(workspacePath), clock: () => now, mutationDidResolver: resolver,
    });
    const url = await listen(server);
    const post = (body: unknown) => fetch(`${url}/v1/mutations`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    const cases = [
      {
        operation: { operation: "submit", target: "verifier", label: "signed-verifier" } as const,
        actorDid: verifier.subjectDid, actorRole: "applicant" as const, seed: applicantSeed,
        record: {
          targetId: verifier.authorizationId,
          scopeCommitment: computeAuthorizationScopeCommitment(createVerifierAuthorizationScopeFixture(verifier)),
        },
      },
      {
        operation: { operation: "submit", target: "auditor", label: "signed-auditor" } as const,
        actorDid: auditor.subjectDid, actorRole: "applicant" as const, seed: applicantSeed,
        record: {
          targetId: auditor.authorizationId,
          scopeCommitment: computeAuthorizationScopeCommitment(createAuditorAuthorizationScopeFixture(auditor)),
        },
      },
      {
        operation: { operation: "submit", target: "recognition", label: "signed-recognition" } as const,
        actorDid: maintainerDid, actorRole: "maintainer" as const, seed: maintainerSeed,
        record: {
          targetId: recognition.recognitionId,
          scopeCommitment: (() => {
            const next = applyWorkspaceOperation(initial, {
              operation: "submit", target: "recognition", label: "signed-recognition",
            });
            const entry = resolveWorkspaceOperationRecord(next, {
              operation: "submit", target: "recognition", label: "signed-recognition",
            });
            if (!("recognition" in entry)) throw new Error("recognition fixture missing");
            return computeRecognitionMutationScopeCommitment(entry.recognition.scope);
          })(),
        },
      },
    ];

    for (const [index, entry] of cases.entries()) {
      const workspace = await loadWorkspaceFromFile(workspacePath);
      const intent = buildIntent(workspace, entry.operation, entry.actorDid, entry.actorRole,
        (index + 50).toString(16), entry.record);
      const wrongScope = { ...intent, scopeCommitment: `0x${"aa".repeat(32)}` };
      expect((await post({ intent: wrongScope, signature: signatureFor(wrongScope, entry.seed), operation: entry.operation })).status).toBe(403);
      expect((await loadWorkspaceFromFile(workspacePath)).operations).toHaveLength(index);
      const response = await post({ intent, signature: signatureFor(intent, entry.seed), operation: entry.operation });
      expect(response.status).toBe(201);
      const result = await response.json();
      expect(result.recordKind).toBe(entry.operation.target === "recognition" ? "recognition" : "authorization");
    }
    const workspace = await loadWorkspaceFromFile(workspacePath);
    expect(workspace.operations).toHaveLength(3);
    expect(Object.keys(workspace.consumedMutationNonces)).toHaveLength(3);
    expect(workspace.snapshot.issuerEntries).toHaveLength(0);
    expect(workspace.snapshot.recognitionEntries[0]?.recognition.status).toBe("proposed");
  }, 60_000);

  it("blocks legacy recognition submit when a governed recognition proposal port is configured", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tr-guarded-recognition-"));
    const workspacePath = join(tempDir, "workspace.json");
    const initial = createOperatorWorkspace({ label: "guarded-recognition" });
    await writeWorkspaceToFile(workspacePath, initial);
    const recognition = createRecognitionScenarioFixture("guarded-recognition");
    const maintainerDid = initial.snapshot.registry.maintainerDids[0];
    if (maintainerDid === undefined) throw new Error("maintainer fixture missing");
    const resolver = createMidnightDidResolver([createMidnightDidLedgerFixture(maintainerDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(maintainerSeed),
      capabilityInvocation: true,
    })]);
    const guardedPort: GovernedRecognitionProposalPort = {
      governanceWorkspacePath: workspacePath,
      admissionStore: { readAccepted: async () => null },
      readBinding: async () => { throw new Error("not called"); },
      readCurrentGovernance: async () => { throw new Error("not called"); },
      prepare: async () => { throw new Error("not called"); },
      execute: async () => { throw new Error("not called"); },
    };
    server = createTrustRegistryApiServer({
      source: createWorkspaceFileSource(workspacePath), clock: () => now,
      mutationDidResolver: resolver, governedRecognitionProposals: guardedPort,
      allowUnsafeDemoMutations: true,
    });
    const url = await listen(server);
    const operation = { operation: "submit", target: "recognition", label: "guarded-recognition" } as const;
    const next = applyWorkspaceOperation(initial, operation);
    const entry = resolveWorkspaceOperationRecord(next, operation);
    if (!("recognition" in entry)) throw new Error("recognition fixture missing");
    const intent = buildIntent(initial, operation, maintainerDid, "maintainer", "77", {
      targetId: recognition.recognitionId,
      scopeCommitment: computeRecognitionMutationScopeCommitment(entry.recognition.scope),
    });
    const post = (path: string, body: unknown) => fetch(`${url}${path}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    expect((await post("/v1/mutations", { intent, signature: signatureFor(intent, maintainerSeed), operation })).status)
      .toBe(403);
    expect((await post("/v1/applications", { target: "recognition", label: "guarded-recognition" })).status)
      .toBe(403);
    const unchanged = await loadWorkspaceFromFile(workspacePath);
    expect(unchanged.operations).toHaveLength(0);
    expect(Object.keys(unchanged.consumedMutationNonces)).toHaveLength(0);
  });
});
