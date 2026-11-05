import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { createOperatorWorkspace, writeWorkspaceToFile } from "../packages/trust-registry-cli/dist/index.js";
import { createTrustRegistryApiServer, createWorkspaceFileSource } from "../packages/trust-registry-api/dist/index.js";
import { createStaticAssetHandler } from "../scripts/serve-static.mjs";
import { expect, test } from "./offline-browser-fixture.mjs";

for (const target of ["issuer", "recognition"]) {
  test(`packaged workspace API carries a fixture ${target} application through both UIs`, async ({ page, allowedLocalOrigins }) => {
    const directory = await mkdtemp(join(tmpdir(), "tr-browser-workspace-handoff-"));
    const workspacePath = join(directory, "workspace.json");
    let server;
    try {
      await writeWorkspaceToFile(workspacePath, createOperatorWorkspace({ label: "Browser workspace handoff" }));
      const staticHandlers = {
        applicant: createStaticAssetHandler({
          distDir: resolve("packages/trust-registry-applicant-portal/dist"), name: "workspace-handoff-applicant",
        }),
        admin: createStaticAssetHandler({
          distDir: resolve("packages/trust-registry-admin-console/dist"), name: "workspace-handoff-admin",
        }),
      };
      server = createTrustRegistryApiServer({
        source: createWorkspaceFileSource(workspacePath),
        allowUnsafeDemoMutations: true,
        nonApiGetHandler: async (request, response) => {
          const url = new globalThis.URL(request.url ?? "/", "http://127.0.0.1");
          const route = /^\/(applicant|admin)(\/.*)?$/u.exec(url.pathname);
          if (route === null) {
            response.writeHead(404).end();
            return;
          }
          request.url = `${route[2] ?? "/"}${url.search}`;
          await staticHandlers[route[1]](request, response);
        },
      });
      await new Promise((done) => server.listen(0, "127.0.0.1", done));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("expected TCP address");
      const base = `http://127.0.0.1:${address.port}`;
      allowedLocalOrigins.add(base);
      page.on("dialog", (dialog) => dialog.accept());

      const label = `Packaged API ${target} handoff`;
      await page.goto(`${base}/applicant/`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator("#demo-application")).toHaveCount(0);
      await page.goto(`${base}/applicant/?demo=1`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await page.locator(`#demo-application [name='target'][value='${target}']`).check();
      await page.locator("#demo-application [name='label']").fill(label);
      await page.locator("#demo-application button[type='submit']").click();
      await expect(page.locator(".alert.success")).toContainText("(proposed)");

      await page.goto(`${base}/admin/`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator("[data-action]")).toHaveCount(0);
      await page.goto(`${base}/admin/?demo=1`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator(".card").filter({ hasText: label })).toContainText("Proposed");
      await page.locator(".card").filter({ hasText: label }).click();
      await page.locator('[data-action="approve"]').click();
      await expect(page.locator(".card").filter({ hasText: label })).toContainText("Authorized");
      await page.locator('[data-action="activate"]').click();
      await expect(page.locator(".card").filter({ hasText: label })).toContainText("Active");

      await page.goto(`${base}/applicant/?demo=1`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator("#trust-records article").filter({ hasText: label })).toBeVisible();
      const activePath = target === "issuer" ? "/v1/authorizations/issuer?status=active"
        : "/v1/recognitions?status=active";
      const activeResponse = await globalThis.fetch(`${base}${activePath}`);
      expect(activeResponse.ok).toBe(true);
      const activeList = await activeResponse.json();
      expect(activeList.entries.some((item) => item.label === label
        && (item.authorization?.status ?? item.recognition?.status) === "active")).toBe(true);
      await expect(page.locator(".source-panel")).toContainText("not deployed ledger evidence");
    } finally {
      await page.close();
      if (server !== undefined) {
        server.closeAllConnections();
        await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
      }
      await rm(directory, { recursive: true, force: true });
    }
  });
}
