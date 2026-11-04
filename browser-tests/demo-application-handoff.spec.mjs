import { createServer } from "node:http";
import { resolve } from "node:path";

import { expect, test } from "./offline-browser-fixture.mjs";
import { createStaticAssetHandler } from "../scripts/serve-static.mjs";

const registryId = "registry:ui-handoff";
const counts = (status) => ({
  proposed: status === "proposed" ? 1 : 0,
  authorized: status === "authorized" ? 1 : 0,
  active: status === "active" ? 1 : 0,
  suspended: 0, revoked: 0, superseded: 0, archived: 0,
});

for (const target of ["issuer", "recognition"]) {
  test(`fixture ${target} application moves from portal to admin and back`, async ({ page, allowedLocalOrigins }) => {
    const staticHandlers = {
      applicant: createStaticAssetHandler({
        distDir: resolve("packages/trust-registry-applicant-portal/dist"), name: "handoff-applicant",
      }),
      admin: createStaticAssetHandler({
        distDir: resolve("packages/trust-registry-admin-console/dist"), name: "handoff-admin",
      }),
    };
    const label = `Browser ${target} handoff`;
    const id = `${target}:browser-handoff:v1`;
    let status;
    const posts = [];
    const entry = target === "recognition" ? {
      label,
      recognition: {
        recognitionId: id, registryId, recognizedAuthorityDid: "did:midnight:undeployed:authority",
        recognizedRegistryId: "registry:external", scope: {
          resourceType: "credential-family", resourceId: "family:ui-handoff:v1",
        }, policyId: "policy:ui-handoff", trustLevel: "approved", proposedAt: "2026-05-20T00:00:00Z",
      },
    } : {
      label,
      authorization: {
        authorizationId: id, registryId, role: "issuer", subjectDid: "did:midnight:undeployed:issuer",
        resourceType: "credential-family", resourceId: `tr:issuer-resource:v1:${"a".repeat(64)}`,
        policyId: "policy:ui-handoff", trustLevel: "approved", proposedAt: "2026-05-20T00:00:00Z",
      },
      evidence: { epoch: { epochId: "epoch:ui-handoff:1", stateRoot: "0xroot" } },
    };
    const record = target === "recognition" ? entry.recognition : entry.authorization;
    const server = createServer(async (request, response) => {
      const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
      const route = /^\/(applicant|admin)(\/.*)?$/u.exec(pathname);
      if (route !== null) {
        request.url = `${route[2] ?? "/"}${new URL(request.url ?? "/", "http://127.0.0.1").search}`;
        await staticHandlers[route[1]](request, response);
        return;
      }
      response.setHeader("content-type", "application/json");
      if (pathname === "/health") {
        response.end(JSON.stringify({ status: "ok", sourceMode: "workspace", registryId }));
        return;
      }
      if (pathname === "/v1/registry/summary") {
        const empty = counts();
        response.end(JSON.stringify({
          registryId, registryLabel: "Midnight Trust Registry", registryDid: "did:midnight:undeployed:registry",
          policyId: "policy:ui-handoff", currentEpochId: "epoch:ui-handoff:1", epochCount: 1,
          issuerCounts: target === "issuer" ? counts(status) : empty,
          recognitionCounts: target === "recognition" ? counts(status) : empty,
          verifierCounts: empty, auditorCounts: empty,
        }));
        return;
      }
      if (request.method === "POST" && pathname === "/v1/applications") {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const submitted = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        posts.push({ pathname, submitted });
        if (submitted.target !== target || submitted.label !== label || status !== undefined) {
          response.statusCode = 409;
          response.end(JSON.stringify({ title: "unexpected application" }));
          return;
        }
        status = "proposed";
        record.status = status;
        response.statusCode = 201;
        response.end(JSON.stringify({ recordKind: target === "recognition" ? "recognition" : "authorization",
          operation: { operation: "submit", target }, entry }));
        return;
      }
      if (request.method === "POST" && pathname.startsWith(`/v1/applications/${target}/`)) {
        const action = pathname.slice(pathname.lastIndexOf("/") + 1);
        posts.push({ pathname, action });
        if (!pathname.includes(encodeURIComponent(id)) || !((action === "approve" && status === "proposed")
          || (action === "activate" && status === "authorized"))) {
          response.statusCode = 409;
          response.end(JSON.stringify({ title: "unexpected transition" }));
          return;
        }
        status = action === "approve" ? "authorized" : "active";
        record.status = status;
        if (status === "authorized") record.authorizedAt = "2026-05-20T00:01:00Z";
        else record[target === "recognition" ? "effectiveFrom" : "activeFrom"] = "2026-05-20T00:02:00Z";
        response.end(JSON.stringify({ recordKind: target === "recognition" ? "recognition" : "authorization",
          operation: { operation: action, target }, entry }));
        return;
      }
      if (pathname.startsWith("/v1/authorizations/") || pathname === "/v1/recognitions") {
        const listed = pathname === (target === "recognition" ? "/v1/recognitions" : "/v1/authorizations/issuer")
          && status !== undefined
          && (!new URL(request.url ?? "/", "http://127.0.0.1").searchParams.has("status") || status === "active");
        response.end(JSON.stringify({ entries: listed ? [entry] : [] }));
        return;
      }
      response.statusCode = 404;
      response.end(JSON.stringify({ title: "not found" }));
    });
    await new Promise((done) => server.listen(0, "127.0.0.1", done));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("expected TCP address");
    const base = `http://127.0.0.1:${address.port}`;
    try {
      allowedLocalOrigins.add(base);
      page.on("dialog", (dialog) => dialog.accept());
      await page.goto(`${base}/applicant/?apiBase=${encodeURIComponent(base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await page.locator("#demo-application [name='target']").selectOption(target);
      await page.locator("#demo-application [name='label']").fill(label);
      await page.locator("#demo-application button[type='submit']").click();
      await expect(page.locator(".alert.success")).toContainText(`Submitted ${label}`);
      await expect(page.locator("#demo-application [name='label']")).toBeEmpty();

      await page.goto(`${base}/admin/?apiBase=${encodeURIComponent(base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator(".card")).toContainText(label);
      await expect(page.locator(".card .status-chip")).toHaveText("Proposed");
      await page.locator('[data-action="approve"]').click();
      await expect(page.locator(".card .status-chip")).toHaveText("Authorized");
      await page.locator('[data-action="activate"]').click();
      await expect(page.locator(".card .status-chip")).toHaveText("Active");

      await page.goto(`${base}/applicant/?apiBase=${encodeURIComponent(base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator("#trust-records article")).toContainText(label);
      await expect(page.locator(".source-panel")).toContainText("not deployed ledger evidence");
      expect(posts).toEqual([
        { pathname: "/v1/applications", submitted: { target, label } },
        { pathname: `/v1/applications/${target}/${encodeURIComponent(id)}/approve`, action: "approve" },
        { pathname: `/v1/applications/${target}/${encodeURIComponent(id)}/activate`, action: "activate" },
      ]);
    } finally {
      await page.close();
      server.closeAllConnections();
      await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    }
  });
}
