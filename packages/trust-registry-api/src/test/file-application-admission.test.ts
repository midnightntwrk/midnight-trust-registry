import { Buffer } from "node:buffer";
import { chmod, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import { deriveJubjubPublicKeyFromSeed, encodeJubjubSignature, signJubjubPayloadFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
  createScopedIdentifier,
  mutationIntentDigestBytes,
  type ApplicationEvidenceSubmission,
  type MutationIntent,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  LocalTrustRegistryIntegrationHarness,
  VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";
import { afterEach, describe, expect, it } from "vitest";

import { FileApplicationAdmissionStore } from "../file-application-admission.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const label = "file-admission";
const harness = new LocalTrustRegistryIntegrationHarness(label);
const workspace = createOperatorWorkspace({ label });
const issuer = createIssuerScenarioFixture(label);
const scope = createIssuerAuthorizationScopeFixture(issuer);
const governedResource = { type: "credentialFamily" as const, id: issuer.resourceId };
const applicationId = createScopedIdentifier("application", "issuer", issuer.authorizationId);
const seed = new Uint8Array(32).fill(47);
const now = new Date(VP_FIXTURE_TIME_MS);
const resolver = createMidnightDidResolver([
  createMidnightDidLedgerFixture(issuer.subjectDid, {
    verificationMethodId: "authentication-1",
    schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
  }),
]);
const signedApplication = (
  nonceByte = "22",
  ids: { applicationId: string; authorizationId: string } = { applicationId, authorizationId: issuer.authorizationId },
) => {
  const intent: MutationIntent = {
    version: "tr-mutation-intent-v1",
    registryId: harness.registryId,
    actorDid: issuer.subjectDid,
    actorKeyId: `${issuer.subjectDid}#authentication-1`,
    actorRole: "applicant",
    action: "apply",
    target: "issuer",
    targetId: ids.applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    payloadCommitment: computePendingApplicationPayloadCommitment({
      applicationId: ids.applicationId, authorizationId: ids.authorizationId, scope, governedResource,
    }),
    nonce: `0x${nonceByte.repeat(32)}`,
    expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
    expectedEpochId: workspace.snapshot.currentEpoch.epochId,
    issuedAt: new Date(VP_FIXTURE_TIME_MS - 60_000).toISOString(),
    expiresAt: new Date(VP_FIXTURE_TIME_MS + 60_000).toISOString(),
  };
  return {
    applicationId: ids.applicationId, authorizationId: ids.authorizationId, scope, governedResource, intent,
    signature: {
      keyId: intent.actorKeyId,
      algorithm: "jubjub-schnorr" as const,
      value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
        seed, mutationIntentDigestBytes(intent),
      ))).toString("hex")}`,
    },
  };
};

const directories: string[] = [];
const storePath = async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-file-admission-"));
  directories.push(directory);
  return join(directory, "admission.json");
};
const store = (path: string, loadWorkspace = async () => workspace) =>
  new FileApplicationAdmissionStore(path, harness.evidenceVerifier.did, resolver, loadWorkspace);
const evidence = () => harness.createApplicationEvidence({
  applicationId: issuer.authorizationId,
  subjectDid: issuer.subjectDid,
  role: "issuer",
  scope,
  governedResource,
});

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("file application admission store", () => {
  it("reconciles a verified Compact archive across instances before a fresh scoped application", async () => {
    const path = await storePath();
    const first = store(path);
    const second = store(path);
    const pending = await first.register(signedApplication(), now);
    const archiveHarness = new LocalTrustRegistryIntegrationHarness(label);
    archiveHarness.proposeIssuer(issuer);
    const eventHash = archiveHarness.archiveIssuer(issuer);
    const bundle = archiveHarness.buildIssuerHistoricalEvidence(issuer);
    const observation = {
      authorizationId: pending.authorizationId,
      binding: pending.binding,
      status: "archived" as const,
      archiveEventHash: `0x${Buffer.from(eventHash).toString("hex")}`,
    };
    const verify = () => {
      new TrustRegistrySimulatorClient(archiveHarness.simulator).verifyIssuerAuthorizationBundle(
        bundle, { expectedRegistryId: archiveHarness.registryId, requireActive: false },
      );
      return bundle.authorization?.status === "archived"
        && bundle.authorization.authorizationId === observation.authorizationId
        && bundle.authorization.subjectDid === observation.binding.subjectDid
        ? bundle.authorization.lifecycleEventRoot : null;
    };
    await expect(first.recordArchived({ ...observation, authorizationId: "auth:substituted" }, verify))
      .rejects.toMatchObject({ reason: "archive-mismatch" });
    expect(await second.readPending(applicationId)).not.toBeNull();
    const archived = await first.recordArchived(observation, verify);
    expect(archived.status).toBe("archived");
    expect(await second.readPending(applicationId)).toBeNull();
    await expect(second.acceptEvidence(applicationId, evidence(), now))
      .rejects.toMatchObject({ reason: "unknown-application" });
    const replacement = signedApplication("23", {
      applicationId: `${applicationId}:replacement`,
      authorizationId: `${issuer.authorizationId}:replacement`,
    });
    expect((await second.register(replacement, now)).status).toBe("pending");
    await expect(first.register(signedApplication("24"), now))
      .rejects.toMatchObject({ reason: "duplicate-application" });
  });

  it("persists signed pending records and redacted accepted evidence across instances", async () => {
    const path = await storePath();
    const first = store(path);
    const second = store(path);
    const pending = await first.register(signedApplication(), now);
    expect(await second.readPending(applicationId)).toEqual(pending);
    const signedEvidence = evidence();
    const receipt = await second.acceptEvidence(applicationId, signedEvidence, now);
    expect(await first.resolveAcceptedEvidence(applicationId)).toEqual({ evidence: signedEvidence, receipt });
    expect(receipt.evidenceCommitment).toBe(signedEvidence.commitment);
    await expect(first.acceptEvidence(applicationId, signedEvidence, now))
      .rejects.toMatchObject({ reason: "already-accepted" });
    await expect(second.register(signedApplication(), now))
      .rejects.toMatchObject({ reason: "nonce-used" });
    const raw = await readFile(path, "utf8");
    expect(raw).not.toContain('"presentation":');
    expect(raw).not.toContain("private-vp-body");
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("admits only one concurrent cross-instance registration", async () => {
    const path = await storePath();
    const outcomes = await Promise.allSettled([
      store(path).register(signedApplication(), now),
      store(path).register(signedApplication(), now),
    ]);
    expect(outcomes.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(await store(path).readPending(applicationId)).not.toBeNull();
  });

  it("rejects mismatched evidence and stale workspace without persisting either", async () => {
    const path = await storePath();
    let currentWorkspace = workspace;
    const admission = store(path, async () => currentWorkspace);
    const changed = { ...workspace, updatedAt: new Date(VP_FIXTURE_TIME_MS + 1_000).toISOString() };
    currentWorkspace = changed;
    await expect(admission.register(signedApplication(), now))
      .rejects.toMatchObject({ reason: "stale-workspace" });
    expect(await admission.readPending(applicationId)).toBeNull();
    currentWorkspace = workspace;
    await admission.register(signedApplication(), now);
    currentWorkspace = {
      ...workspace,
      snapshot: {
        ...workspace.snapshot,
        policy: { ...workspace.snapshot.policy, version: "v2" },
      },
    };
    await expect(admission.acceptEvidence(applicationId, evidence(), now))
      .rejects.toMatchObject({ reason: "stale-policy" });
    currentWorkspace = workspace;
    await expect(admission.acceptEvidence(applicationId, {
      ...evidence(), presentation: "private-vp-body",
    } as ApplicationEvidenceSubmission, now)).rejects.toThrow();
    const tampered = { ...evidence(), envelope: { ...evidence().envelope, subjectDid: harness.maintainerDid } };
    await expect(admission.acceptEvidence(applicationId, tampered, now))
      .rejects.toMatchObject({ reason: "mismatched-evidence" });
    expect(await admission.resolveAcceptedEvidence(applicationId)).toBeNull();
  });

  it("rechecks the live workspace after signature verification before committing", async () => {
    const path = await storePath();
    let reads = 0;
    const changed = { ...workspace, updatedAt: new Date(VP_FIXTURE_TIME_MS + 1_000).toISOString() };
    const admission = store(path, async () => (++reads === 1 ? workspace : changed));
    await expect(admission.register(signedApplication(), now))
      .rejects.toMatchObject({ reason: "stale-workspace" });
    expect(reads).toBe(2);
    expect(await admission.readPending(applicationId)).toBeNull();
  });

  it("fails closed for malformed, public-readable, and symlinked state files", async () => {
    const path = await storePath();
    await writeFile(path, "{bad-json", { mode: 0o600 });
    await expect(store(path).readPending(applicationId)).rejects.toMatchObject({
      name: "InvalidApplicationAdmissionFileError",
    });
    await writeFile(path, "{}", { mode: 0o600 });
    await chmod(path, 0o644);
    await expect(store(path).readPending(applicationId)).rejects.toMatchObject({
      name: "InvalidApplicationAdmissionFileError",
    });
    await rm(path);
    const target = join(join(path, ".."), "target.json");
    await writeFile(target, "{}", { mode: 0o600 });
    await symlink(target, path);
    await expect(store(path).readPending(applicationId)).rejects.toMatchObject({
      name: "InvalidApplicationAdmissionFileError",
    });
  });
});
