import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { resolve } from "node:path";

import { expect, test } from "./offline-browser-fixture.mjs";
import { createStaticAssetHandler } from "../scripts/serve-static.mjs";

const recognitionId = "recognition:external:ui-demo";
const nonce = `0x${"a".repeat(64)}`;
const receiptId = `0x${"b".repeat(64)}`;
const evidenceCommitment = `0x${"c".repeat(64)}`;
const epochId = "epoch:recognition-ui:1";
const policyId = "policy:recognition-ui:1";
const authorityDid = "did:web:authority.example";
const issuerDid = `did:midnight:undeployed:${"d".repeat(64)}`;
const issuerResourceId = `tr:issuer-resource:v1:${"e".repeat(64)}`;
const at = "2026-10-15T00:00:00Z";

test("applicant inspects and downloads bounded historical recognition and authorization claims", async ({ page, allowedLocalOrigins }) => {
  const staticHandler = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-applicant-portal/dist"),
    name: "applicant-recognition-browser-test",
  });
  const requests = [];
  const receipt = { recognitionId, receiptId, evidenceCommitment, acceptedAt: "2026-10-15T00:01:00Z" };
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path !== "/health" && !path.startsWith("/v1/")) {
      response.setHeader("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
      await staticHandler(request, response);
      return;
    }
    response.setHeader("content-type", "application/json");
    if (path === "/health") {
      response.setHeader("set-cookie", "fixture-session=1; HttpOnly; SameSite=Strict; Path=/");
      response.end(JSON.stringify({ status: "ok", sourceMode: "workspace", registryId: "registry:recognition-ui" }));
      return;
    }
    if (path === "/v1/registry/summary") {
      const empty = { proposed: 0, authorized: 0, active: 0, suspended: 0,
        revoked: 0, superseded: 0, archived: 0 };
      response.end(JSON.stringify({ registryId: "registry:recognition-ui", registryLabel: "Recognition UI fixture",
        currentEpochId: epochId, issuerCounts: empty, verifierCounts: empty,
        auditorCounts: empty, recognitionCounts: empty }));
      return;
    }
    if (path.startsWith("/v1/recognition-evidence/")) {
      if (!request.headers.cookie?.includes("fixture-session=1")) {
        response.statusCode = 401;
        response.end(JSON.stringify({ title: "fixture session required" }));
        return;
      }
      const base = `/v1/recognition-evidence/${encodeURIComponent(recognitionId)}`;
      if (path === `${base}/accepted` && request.method === "GET") {
        requests.push({ path, method: request.method });
        response.end(JSON.stringify(receipt));
        return;
      }
      if (request.method === "POST" && (path === `${base}/challenges` || path === `${base}/submissions`)) {
        let raw = "";
        for await (const chunk of request) raw += chunk;
        const body = JSON.parse(raw);
        requests.push({ path, method: request.method, body });
        if (path.endsWith("/challenges")) {
          response.end(JSON.stringify({ recognitionId, nonce, challengeHash: nonce,
            issuedAt: at, expiresAt: "2026-10-15T00:05:00Z" }));
        } else if (body.nonce === nonce) {
          response.end(JSON.stringify({ recognitionId, evidenceCommitment, receipt,
            expiresAt: "2026-10-15T00:05:00Z" }));
        } else {
          response.statusCode = 400;
          response.end(JSON.stringify({ title: "challenge nonce mismatch" }));
        }
        return;
      }
    }
    if (path === "/v1/recognitions/evaluate/evidence" && request.method === "POST") {
      let raw = "";
      for await (const chunk of request) raw += chunk;
      const query = JSON.parse(raw);
      requests.push({ path, method: request.method, body: query });
      response.end(JSON.stringify({ evaluatedAt: query.at, statusAtTime: "active", trustedAtTime: true,
        epoch: { epochId }, bundle: { epoch: { epochId }, policy: { policyId },
          recognition: { recognizedAuthorityDid: query.recognizedAuthorityDid,
            recognizedRegistryId: query.recognizedRegistryId,
            scope: { resourceType: query.scopeResourceType, resourceId: query.scopeResourceId } } } }));
      return;
    }
    if (path === "/v1/authorizations/evaluate/evidence" && request.method === "POST") {
      let raw = "";
      for await (const chunk of request) raw += chunk;
      const query = JSON.parse(raw);
      requests.push({ path, method: request.method, body: query });
      response.end(JSON.stringify({ evaluatedAt: query.at, statusAtTime: "active", trustedAtTime: true,
        epoch: { epochId }, bundle: { epoch: { epochId }, policy: { policyId },
          authorization: { role: query.role, subjectDid: query.subjectDid, resourceId: query.resourceId } } }));
      return;
    }
    response.end(JSON.stringify({ entries: [] }));
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    allowedLocalOrigins.add(base);
    await page.goto(`${base}/?apiBase=${encodeURIComponent(base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator(".journey-prerequisite")).toContainText("host must authenticate your session");
    await page.locator(".advanced-tools > summary").click();
    await page.locator('[data-workflow="Recover external recognition"] > summary').click();
    const recovery = page.locator("[data-recognition-recovery-form]");
    await recovery.locator("[name='recognitionId']").fill(recognitionId);
    await page.locator("[data-recognition-challenge]").click();
    await expect(page.locator("[data-recognition-challenge-context]")).toContainText(nonce);
    await page.locator("[data-recognition-accreditation-form] [name='signedAccreditation']")
      .fill(JSON.stringify({ nonce, fixtureSignature: "signed outside browser", fixtureVp: {} }));
    await page.locator("[data-recognition-accreditation-form] button[type='submit']").click();
    await expect(page.locator("[data-recognition-recovery-result]"))
      .toContainText("Governance approval is still required");
    await expect(page.locator("[data-recognition-admission]")).toContainText(receiptId);
    await page.locator("[data-recognition-accepted]").click();
    await expect(page.locator("[data-recognition-recovery-result]"))
      .toContainText("Accepted accreditation receipt recovered");
    expect(requests.find((entry) => entry.path.endsWith("/submissions"))?.body.nonce).toBe(nonce);

    await page.locator('[data-workflow="Historical recognition evidence"] > summary').click();
    const historical = page.locator("[data-historical-recognition]");
    await historical.locator("[name='recognizedAuthorityDid']").fill(authorityDid);
    await historical.locator("[name='recognizedRegistryId']").fill("external:registry");
    await historical.locator("[name='scopeResourceType']").fill("credential-family");
    await historical.locator("[name='scopeResourceId']").fill("degree");
    await historical.locator("[name='at']").fill(at);
    await historical.getByRole("button", { name: "Inspect recognition evidence" }).click();
    const result = page.locator("[data-historical-recognition-result]");
    await expect(result).toContainText("Unverified API claim");
    await expect(result).toContainText(epochId);
    const pendingDownload = page.waitForEvent("download");
    await page.locator("[data-download-historical-recognition]").click();
    const download = await pendingDownload;
    expect(download.suggestedFilename()).toBe("midnight-trust-registry-historical-recognition-evidence.json");
    const exported = JSON.parse(await readFile(await download.path(), "utf8"));
    expect(exported).toMatchObject({
      format: "midnight-trust-registry-unverified-api-claim-v1",
      kind: "historical-recognition-evidence", verifiedFinality: false,
      query: { recognizedAuthorityDid: authorityDid, recognizedRegistryId: "external:registry",
        scopeResourceType: "credential-family", scopeResourceId: "degree", at },
      result: { evaluatedAt: at, bundle: { epoch: { epochId }, policy: { policyId } } },
    });
    await historical.locator("[name='scopeResourceId']").fill("another-degree");
    await expect(result).toHaveCount(0);
    await expect(page.locator("[data-download-historical-recognition]")).toHaveCount(0);
    await page.locator("[data-refresh]").click();
    await expect(historical.locator("[name='scopeResourceId']")).toHaveValue("another-degree");
    await expect(result).toHaveCount(0);
    expect(requests.filter((entry) => entry.path === "/v1/recognitions/evaluate/evidence")).toHaveLength(1);

    await page.locator('[data-workflow="Historical authorization evidence"] > summary').click();
    const authorization = page.locator("[data-historical-authorization]");
    await authorization.locator("[name='subjectDid']").fill(issuerDid);
    await authorization.locator("[name='resourceId']").fill(issuerResourceId);
    await authorization.locator("[name='at']").fill(at);
    await authorization.getByRole("button", { name: "Inspect authorization evidence" }).click();
    const authorizationResult = page.locator("[data-historical-result]");
    await expect(authorizationResult).toContainText("Unverified API claim");
    const pendingAuthorizationDownload = page.waitForEvent("download");
    await page.locator("[data-download-historical-authorization]").click();
    const authorizationDownload = await pendingAuthorizationDownload;
    expect(authorizationDownload.suggestedFilename()).toBe("midnight-trust-registry-historical-authorization-evidence.json");
    const exportedAuthorization = JSON.parse(await readFile(await authorizationDownload.path(), "utf8"));
    expect(exportedAuthorization).toMatchObject({
      format: "midnight-trust-registry-unverified-api-claim-v1",
      kind: "historical-authorization-evidence", verifiedFinality: false,
      query: { role: "issuer", subjectDid: issuerDid, resourceId: issuerResourceId, at },
      result: { evaluatedAt: at, bundle: { epoch: { epochId }, policy: { policyId } } },
    });
    await authorization.locator("[name='resourceId']").fill("another-resource");
    await expect(authorizationResult).toHaveCount(0);
    await expect(page.locator("[data-download-historical-authorization]")).toHaveCount(0);
    await page.locator("[data-refresh]").click();
    await expect(authorization.locator("[name='resourceId']")).toHaveValue("another-resource");
    await expect(authorizationResult).toHaveCount(0);
    expect(requests.filter((entry) => entry.path === "/v1/authorizations/evaluate/evidence")).toHaveLength(1);
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
  }
});
