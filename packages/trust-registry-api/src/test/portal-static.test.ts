import { createServer } from "node:http";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import { createDemoSnapshot } from "@midnight-ntwrk/trust-registry-cli";

import { createPortalStaticHandler } from "../portal-static.js";
import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";

describe("same-origin local portals", () => {
  it("requires both packaged asset roots before listening", async () => {
    const root = await mkdtemp(join(tmpdir(), "tr-portals-"));
    try {
      await mkdir(join(root, "admin"));
      await writeFile(join(root, "admin", "index.html"), "<html>admin</html>");
      await expect(createPortalStaticHandler(root)).rejects.toThrow();
      await writeFile(join(root, "admin", "index.js"), "export {};");
      await mkdir(join(root, "applicant"));
      await writeFile(join(root, "applicant", "index.html"), "<html>applicant</html>");
      await expect(createPortalStaticHandler(root)).rejects.toThrow();
      await writeFile(join(root, "applicant", "index.js"), "export {};");
      await expect(createPortalStaticHandler(root)).resolves.toBeTypeOf("function");
      await rm(join(root, "applicant", "index.html"));
      await symlink(join(root, "admin", "index.html"), join(root, "applicant", "index.html"));
      await expect(createPortalStaticHandler(root)).rejects.toThrow(/regular packaged files/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("serves only same-origin static files with restrictive browser policy", async () => {
    const root = await mkdtemp(join(tmpdir(), "tr-portals-"));
    let server: ReturnType<typeof createServer> | undefined;
    try {
      for (const role of ["admin", "applicant"]) {
        await mkdir(join(root, role));
        await writeFile(join(root, role, "index.html"), `<html>${role}</html>`);
        await writeFile(join(root, role, "index.js"), "export const ready = true;");
        await writeFile(join(root, role, "index.js.map"), "private source map");
      }
      await writeFile(join(root, "secret.html"), "private material");
      await symlink(join(root, "secret.html"), join(root, "admin", "secret.html"));
      const handler = await createPortalStaticHandler(root);
      server = createServer((request, response) => { void handler(request, response); });
      await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
      const bound = server.address();
      if (bound === null || typeof bound === "string") throw new Error("Missing test listener");
      const base = `http://127.0.0.1:${bound.port}`;
      const redirect = await fetch(`${base}/admin?apiBase=ignored`, { redirect: "manual" });
      expect(redirect.status).toBe(308);
      expect(redirect.headers.get("location")).toBe("/admin/?apiBase=ignored");
      const admin = await fetch(`${base}/admin/`);
      expect(admin.status).toBe(200);
      expect(admin.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(admin.headers.get("content-security-policy")).toContain("connect-src 'self'");
      expect(admin.headers.get("x-content-type-options")).toBe("nosniff");
      expect(await admin.text()).toBe("<html>admin</html>");
      expect(await (await fetch(`${base}/applicant/index.js`)).text()).toBe("export const ready = true;");
      for (const path of ["/admin/secret.html", "/admin/index.js.map", "/admin/%2e%2e/secret.html",
        "/admin/%2fsecret.html", "/applicant/missing.js"]) {
        const response = await fetch(`${base}${path}`);
        expect(response.status).not.toBe(200);
        expect(await response.text()).not.toContain("private material");
      }
    } finally {
      if (server?.listening) {
        await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
      }
      await rm(root, { recursive: true, force: true });
    }
  });

  it("keeps API routes separate from same-origin portal routes", async () => {
    const root = await mkdtemp(join(tmpdir(), "tr-portals-server-"));
    let server: ReturnType<typeof createTrustRegistryApiServer> | undefined;
    try {
      for (const role of ["admin", "applicant"]) {
        await mkdir(join(root, role));
        await writeFile(join(root, role, "index.html"), `<html>${role}</html>`);
        await writeFile(join(root, role, "index.js"), "export {};");
      }
      server = createTrustRegistryApiServer({
        source: createInMemorySource(createDemoSnapshot()),
        nonApiGetHandler: await createPortalStaticHandler(root),
      });
      await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
      const bound = server.address();
      if (bound === null || typeof bound === "string") throw new Error("Missing test listener");
      const base = `http://127.0.0.1:${bound.port}`;
      expect(await (await fetch(`${base}/admin/`)).text()).toBe("<html>admin</html>");
      expect(await (await fetch(`${base}/applicant/`)).text()).toBe("<html>applicant</html>");
      const registry = await fetch(`${base}/v1/registry`);
      expect(registry.status).toBe(200);
      expect(registry.headers.get("content-type")).toContain("application/json");
      const malformed = await fetch(`${base}/admin/%E0`);
      expect(malformed.status).toBe(400);
      expect(await malformed.text()).not.toContain("URI malformed");
    } finally {
      if (server?.listening) {
        await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
      }
      await rm(root, { recursive: true, force: true });
    }
  });
});
