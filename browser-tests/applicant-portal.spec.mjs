import { resolve } from "node:path";

import { expect, test } from "./offline-browser-fixture.mjs";

import { applicationDraft, demoRegistryId, presentationForNonce, signDigest, startHost } from "../scripts/demo-auditor-admission.mjs";

const cases = [
  {
    role: "issuer",
    scope: {
      version: "tr-scope-v1", role: "issuer", credentialFamilyId: "family:degree:v1",
      schemaId: "schema:degree", schemaVersion: "1.0.0",
      credentialDefinitionId: "definition:degree:v1", statusMethod: "status:registry:v1",
    },
    governedResourceType: "credentialFamily",
  },
  {
    role: "verifier",
    scope: {
      version: "tr-scope-v1", role: "verifier", requestProfileId: "profile:age-gate:v1",
      purpose: "age-gate", credentialScopeCommitment: `0x${"aa".repeat(32)}`,
      allowedAttributes: ["attribute:age"], allowedPredicates: ["predicate:over-18"],
      disclosureLevel: "minimal",
    },
  },
  {
    role: "auditor",
    scope: {
      version: "tr-scope-v1", role: "auditor", requestProfileId: "profile:audit:v1",
      purpose: "compliance-review", credentialScopeCommitment: `0x${"bb".repeat(32)}`,
      allowedAttributes: ["company-id"], allowedPredicates: ["is-licensed"],
      disclosureLevel: "restricted",
    },
  },
  {
    role: "maintainer",
    scope: { version: "tr-scope-v1", role: "maintainer", registryId: demoRegistryId },
  },
];

for (const applicant of cases) {
  test(`${applicant.role} application completes the real-browser admission flow`, async ({ page, allowedLocalOrigins }) => {
    const host = await startHost(0, resolve("packages/trust-registry-applicant-portal/dist"), applicant.scope);
    try {
      allowedLocalOrigins.add(host.base);
      await page.goto(`${host.base}/?apiBase=${encodeURIComponent(host.base)}`);
      const form = page.locator(`[data-${applicant.role}-application-form]`);
      const applicationId = `application:${applicant.role}:browser:v1`;
      const draft = {
        applicationId,
        authorizationId: `auth:${applicant.role}:browser:v1`,
        actorDid: applicationDraft.actorDid,
        actorKeyId: applicationDraft.actorKeyId,
        ...applicant.scope,
        ...(applicant.governedResourceType === undefined ? {} : { governedResourceType: applicant.governedResourceType }),
      };
      for (const [name, value] of Object.entries(draft)) {
        if (["version", "role", "registryId"].includes(name)) continue;
        const field = form.locator(`[name='${name}']`);
        if (name === "governedResourceType") await field.selectOption(value);
        else await field.fill(Array.isArray(value) ? value.join("\n") : value);
      }
      await form.locator(`[data-prepare-${applicant.role}]`).click();
      const digest = (await page.locator(`[data-${applicant.role}-digest]`).innerText()).split(": ")[1];
      expect(digest).toMatch(/^0x[0-9a-f]{64}$/u);
      const signatureField = form.locator(`[name='${applicant.role === "auditor" ? "auditorSignature" : "memberSignature"}']`);
      await signatureField.fill(`0x${"00".repeat(96)}`);
      const forgedResponse = page.waitForResponse((response) => response.url().endsWith("/v1/pending-applications")
        && response.request().method() === "POST");
      await form.locator("button[type='submit']").click();
      expect((await forgedResponse).status()).not.toBe(201);
      expect(host.receipts.size).toBe(0);

      await signatureField.fill(signDigest(digest));
      const acceptedResponse = page.waitForResponse((response) => response.url().endsWith("/v1/pending-applications")
        && response.request().method() === "POST");
      await form.locator("button[type='submit']").click();
      expect((await acceptedResponse).status()).toBe(201);
      await expect(page.locator("[data-application-challenge]")).toBeVisible();
      await expect(page.locator("body")).toContainText(`Pending ${applicant.role} application ${applicationId} registered`);

      const challengeResponse = page.waitForResponse((response) =>
        decodeURIComponent(new URL(response.url()).pathname) === `/v1/application-evidence/${applicationId}/challenges`);
      await page.locator("[data-application-challenge]").click();
      const challenge = await (await challengeResponse).json();
      expect(challenge.nonce).toMatch(/^0x[0-9a-f]{64}$/u);
      const presentation = await presentationForNonce(challenge.nonce, applicant.scope);
      await page.locator("[data-application-vp-form] [name='presentation']").fill(JSON.stringify(presentation));
      await page.locator("[data-application-vp-form] button[type='submit']").click();
      await expect(page.locator("[data-accepted-evidence]")).toBeVisible();
      await expect(page.locator("body")).toContainText(`${applicant.role} evidence accepted`);
      expect(host.receipts.size).toBe(1);
      expect(await page.locator("body").innerText()).not.toContain("private-presentation-payload");
      await expect(page.locator("[data-application-vp-form]")).toHaveCount(0);
    } finally {
      await page.close();
      host.server.closeAllConnections();
      await new Promise((resolveClose, reject) => host.server.close((error) => error ? reject(error) : resolveClose()));
    }
  });
}
