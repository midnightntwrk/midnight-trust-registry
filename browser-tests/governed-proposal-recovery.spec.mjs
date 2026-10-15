import { Buffer } from "node:buffer";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect, test } from "@playwright/test";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
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

const signPrepared = (maintainer, prepared) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  return {
    keyId: hex(maintainer.keyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: hex(encodeJubjubSignature(signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    bytes(prepared.registryId),
    bytes(prepared.policyCommitment),
    bytes(prepared.actionKind),
    bytes(prepared.actionPayloadHash),
    BigInt(prepared.actionSequence),
    ))),
  };
};

test("admin recovers an accepted Compact proposal after its HTTP response is lost", async ({ page }) => {
  const harness = new LocalTrustRegistryIntegrationHarness("admin-browser-proposal-recovery");
  const second = createMaintainerScenarioFixture("admin-browser-second");
  const third = createMaintainerScenarioFixture("admin-browser-third");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const issuer = createIssuerScenarioFixture("admin-browser-candidate");
  const scope = createIssuerAuthorizationScopeFixture(issuer);
  const evidence = harness.createApplicationEvidence({
    applicationId: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    scope,
    governedResource: {
      type: issuerResourceTypeDetails[issuer.resourceType].governedType,
      id: issuer.resourceId,
    },
  });
  const binding = {
    registryId: evidence.envelope.registryId,
    applicationId: evidence.envelope.applicationId,
    subjectDid: evidence.envelope.subjectDid,
    evidenceVerifierDid: evidence.envelope.evidenceVerifierDid,
    role: "issuer",
    policyId: evidence.envelope.policyId,
    policyVersion: evidence.envelope.policyVersion,
    scope,
    scopeCommitment: evidence.envelope.scopeCommitment,
    governedResource: evidence.envelope.governedResource,
  };
  const directory = await mkdtemp(join(tmpdir(), "tr-admin-browser-recovery-"));
  const journal = new FileProposalSubmissionJournal(join(directory, "submissions.json"));
  let finalizedLedger = harness.simulator.getLedger();
  let executions = 0;
  const staticHandler = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"),
    name: "admin-browser-recovery",
  });
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "browser-recovery" }) },
    proposalAdmission: {
      resolvePendingApplication: async () => ({
        authorizationId: issuer.authorizationId, binding, status: "pending", createdAt: "2026-05-20T00:00:00.000Z",
      }),
      resolveAcceptedEvidence: async () => ({
        evidence,
        receipt: { receiptId: `0x${"b2".repeat(32)}`, evidenceCommitment: evidence.commitment,
          acceptedAt: "2026-05-20T00:01:00.000Z" },
      }),
    },
    proposalSubmissionJournal: journal,
    governedIssuerProposals: {
      prepare: async () => harness.prepareIssuerProposalAction(issuer, evidence),
      execute: async (_, submitted, signers, verifierSignature) => {
        executions += 1;
        harness.executeIssuerProposalWithSignatures(issuer, submitted, signers, verifierSignature);
        throw new Error("HTTP response lost after Compact acceptance");
      },
      resolve: async (authorizationId) => resolveCompactProposalObservation(
        async () => finalizedLedger, harness.registryId, "issuer", authorizationId,
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
    await page.locator("[data-proposal-id]").fill(issuer.authorizationId);
    await page.locator("[data-proposal-evidence]").fill(JSON.stringify(evidence));
    await page.locator("[data-proposal-prepare] button[type='submit']").click();
    const preparedNode = page.locator("[data-proposal-context]");
    await expect(preparedNode).toBeVisible();
    const prepared = JSON.parse(await preparedNode.textContent());
    const verifierSignature = harness.signIssuerProposalEvidence(
      harness.prepareIssuerProposalAction(issuer, evidence),
    );
    await page.locator("[data-proposal-signers]").fill(JSON.stringify([
      signPrepared(second, prepared), signPrepared(third, prepared),
    ]));
    await page.locator("[data-proposal-verifier-signature]").fill(hex(encodeJubjubSignature(verifierSignature)));
    await page.locator("[data-proposal-submit] button[type='submit']").click();
    await expect(page.locator("body")).toContainText("proposal submission outcome unknown");
    await expect(page.locator("[data-proposal-submit]")).toHaveCount(0);
    expect(executions).toBe(1);
    expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(1n);
    await page.locator("[data-proposal-resolve]").click();
    await expect(page.locator("body")).toContainText("Proposal not observed");
    finalizedLedger = harness.simulator.getLedger();
    await page.locator("[data-proposal-resolve]").click();
    await expect(page.locator("body")).toContainText("Compact issuer proposal observed");
    expect((await journal.read("issuer", issuer.authorizationId))?.state).toBe("observed");
    expect(executions).toBe(1);
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((closed, reject) => server.close((error) => error ? reject(error) : closed()));
    await rm(directory, { recursive: true, force: true });
  }
});
