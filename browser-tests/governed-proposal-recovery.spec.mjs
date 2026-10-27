import { Buffer } from "node:buffer";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect, test } from "@playwright/test";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  issuerResourceTypeDetails,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  createTrustRegistryApiServer,
  FileProposalSubmissionJournal,
  resolveCompactProposalObservation,
} from "../packages/trust-registry-api/dist/index.js";
import { createStaticAssetHandler } from "../scripts/serve-static.mjs";

const bytes = (hex) => Buffer.from(hex.slice(2), "hex");
const hex = (value) => `0x${Buffer.from(value).toString("hex")}`;

const signPrepared = (harness, maintainer, prepared) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const ledger = harness.simulator.getLedger();
  return {
    keyId: hex(maintainer.keyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: hex(encodeJubjubSignature(signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      ledger.registryId,
      ledger.deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"),
      ledger.governancePolicyCommitment,
      bytes(prepared.actionKind),
      bytes(prepared.actionPayloadHash),
      BigInt(prepared.actionSequence),
    ))),
  };
};

const scenarioFor = (role, harness) => {
  if (role === "issuer") {
    const fixture = createIssuerScenarioFixture("admin-browser-candidate");
    return {
      id: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      scope: createIssuerAuthorizationScopeFixture(fixture),
      governedResource: { type: issuerResourceTypeDetails[fixture.resourceType].governedType, id: fixture.resourceId },
      prepare: (evidence) => harness.prepareIssuerProposalAction(fixture, evidence),
      execute: (evidence, signers, signature) => harness.executeIssuerProposalWithSignatures(fixture, evidence, signers, signature),
      signEvidence: (prepared) => harness.signIssuerProposalEvidence(prepared),
      portName: "governedIssuerProposals",
    };
  }
  if (role === "verifier") {
    const fixture = createVerifierScenarioFixture("admin-browser-candidate");
    return {
      id: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      scope: createVerifierAuthorizationScopeFixture(fixture),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId },
      prepare: (evidence) => harness.prepareVerifierProposalAction(fixture, evidence),
      execute: (evidence, signers, signature) => harness.executeVerifierProposalWithSignatures(fixture, evidence, signers, signature),
      signEvidence: (prepared) => harness.signVerifierProposalEvidence(prepared),
      portName: "governedVerifierProposals",
    };
  }
  if (role === "auditor") {
    const fixture = createAuditorScenarioFixture("admin-browser-candidate");
    return {
      id: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      scope: createAuditorAuthorizationScopeFixture(fixture),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId },
      prepare: (evidence) => harness.prepareAuditorProposalAction(fixture, evidence),
      execute: (evidence, signers, signature) => harness.executeAuditorProposalWithSignatures(fixture, evidence, signers, signature),
      signEvidence: (prepared) => harness.signAuditorProposalEvidence(prepared),
      portName: "governedAuditorProposals",
    };
  }
  const fixture = createMaintainerScenarioFixture("admin-browser-candidate");
  return {
    id: fixture.maintainerId,
    subjectDid: fixture.subjectDid,
    scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
    governedResource: { type: "registry", id: harness.registryId },
    prepare: (evidence) => harness.prepareMaintainerProposalAction(fixture, evidence),
    execute: (evidence, signers, signature) => harness.executeMaintainerProposalWithSignatures(fixture, evidence, signers, signature),
    signEvidence: (prepared) => harness.signMaintainerProposalEvidence(prepared),
    portName: "governedMaintainerProposals",
  };
};

for (const role of ["issuer", "verifier", "auditor", "maintainer"]) test(`admin recovers an accepted ${role} proposal after its HTTP response is lost`, async ({ page }) => {
  const harness = new LocalTrustRegistryIntegrationHarness(`admin-browser-${role}-proposal-recovery`);
  const second = createMaintainerScenarioFixture("admin-browser-second");
  const third = createMaintainerScenarioFixture("admin-browser-third");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const scenario = scenarioFor(role, harness);
  const { scope } = scenario;
  const evidence = harness.createApplicationEvidence({
    applicationId: scenario.id,
    subjectDid: scenario.subjectDid,
    role,
    scope,
    governedResource: scenario.governedResource,
  });
  const binding = {
    registryId: evidence.envelope.registryId,
    applicationId: evidence.envelope.applicationId,
    subjectDid: evidence.envelope.subjectDid,
    evidenceVerifierDid: evidence.envelope.evidenceVerifierDid,
    role,
    policyId: evidence.envelope.policyId,
    policyVersion: evidence.envelope.policyVersion,
    scope,
    scopeCommitment: evidence.envelope.scopeCommitment,
    governedResource: evidence.envelope.governedResource,
  };
  const directory = await mkdtemp(join(tmpdir(), `tr-admin-${role}-browser-recovery-`));
  const journal = new FileProposalSubmissionJournal(join(directory, "submissions.json"));
  let finalizedLedger = harness.simulator.getLedger();
  const beforeActionCount = finalizedLedger.governanceActionCount;
  let executions = 0;
  const staticHandler = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"),
    name: "admin-browser-recovery",
  });
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "browser-recovery" }) },
    proposalAdmission: {
      resolvePendingApplication: async () => ({
        authorizationId: scenario.id, binding, status: "pending", createdAt: "2026-05-20T00:00:00.000Z",
      }),
      resolveAcceptedEvidence: async () => ({
        evidence,
        receipt: { receiptId: `0x${"b2".repeat(32)}`, evidenceCommitment: evidence.commitment,
          acceptedAt: "2026-05-20T00:01:00.000Z" },
      }),
    },
    proposalSubmissionJournal: journal,
    [scenario.portName]: {
      prepare: async () => scenario.prepare(evidence),
      preflightSubmission: async (authorizationId, submitted) => {
        expect(authorizationId).toBe(scenario.id);
        expect(submitted.commitment).toBe(evidence.commitment);
        expect(executions).toBe(0);
      },
      execute: async (_, submitted, signers, verifierSignature) => {
        executions += 1;
        scenario.execute(submitted, signers, verifierSignature);
        throw new Error("HTTP response lost after Compact acceptance");
      },
      resolve: async (authorizationId) => resolveCompactProposalObservation(
        async () => finalizedLedger, harness.registryId, role, authorizationId,
      ),
    },
    nonApiGetHandler: staticHandler,
  });
  try {
    await new Promise((listening) => server.listen(0, "127.0.0.1", listening));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("expected TCP address");
    const base = `http://127.0.0.1:${address.port}`;
    page.on("dialog", (dialog) => dialog.accept());
    await page.goto(`${base}/?apiBase=${encodeURIComponent(base)}`);
    await expect(page.locator("[data-proposal-prepare] button[type='submit']")).toBeEnabled();
    await page.locator("[data-proposal-role]").selectOption(role);
    await page.locator("[data-proposal-id]").fill(scenario.id);
    await page.locator("[data-proposal-evidence]").fill(JSON.stringify(evidence));
    await page.locator("[data-proposal-prepare] button[type='submit']").click();
    const preparedNode = page.locator("[data-proposal-context]");
    await expect(preparedNode).toBeVisible();
    const prepared = JSON.parse(await preparedNode.textContent());
    const verifierSignature = scenario.signEvidence(scenario.prepare(evidence));
    const forgedContext = { ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() };
    await page.locator("[data-proposal-signers]").fill(JSON.stringify([
      signPrepared(harness, second, forgedContext), signPrepared(harness, third, prepared),
    ]));
    await page.locator("[data-proposal-verifier-signature]").fill(hex(encodeJubjubSignature(verifierSignature)));
    await page.locator("[data-proposal-submit] button[type='submit']").click();
    await expect(page.locator("body")).toContainText("A maintainer vote does not sign the prepared governed action");
    expect(await journal.read(role, scenario.id)).toBeNull();
    expect(executions).toBe(0);
    await page.locator("[data-proposal-signers]").fill(JSON.stringify([
      signPrepared(harness, second, prepared), signPrepared(harness, third, prepared),
    ]));
    await page.locator("[data-proposal-submit] button[type='submit']").click();
    await expect(page.locator("body")).toContainText("proposal submission outcome unknown");
    await expect(page.locator("[data-proposal-submit]")).toHaveCount(0);
    expect(executions).toBe(1);
    expect(harness.simulator.getLedger().governanceActionCount).toBeGreaterThan(beforeActionCount);
    await page.locator("[data-proposal-resolve]").click();
    await expect(page.locator("body")).toContainText("Proposal not observed");
    finalizedLedger = harness.simulator.getLedger();
    await page.locator("[data-proposal-resolve]").click();
    await expect(page.locator("body")).toContainText(`Compact ${role} proposal observed`);
    expect((await journal.read(role, scenario.id))?.state).toBe("observed");
    expect(executions).toBe(1);
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((closed, reject) => server.close((error) => error ? reject(error) : closed()));
    await rm(directory, { recursive: true, force: true });
  }
});
