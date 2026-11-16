import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { createServer } from "node:net";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createLongFormOffchainMidnightDIDString, CurveType, KeyType } from "@midnight-ntwrk/midnight-did-domain";

import { test, expect } from "./offline-browser-fixture.mjs";
import { createOperatorWorkspace, writeWorkspaceToFile } from "../packages/trust-registry-cli/dist/index.js";

async function reserveLoopbackPort() {
  const listener = createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const address = listener.address();
  if (address === null || typeof address === "string") throw new Error("Expected loopback port");
  await new Promise((resolve) => listener.close(resolve));
  return address.port;
}

async function startPackagedHost({ workspacePath, challengeStorePath, portalRoot, port }) {
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ["packages/trust-registry-api/bin/trust-registry-api.mjs",
    "serve", "--workspace", workspacePath, "--port", String(port),
    "--fixture-offchain-auth-store", challengeStorePath,
    "--fixture-portal-root", portalRoot], {
    cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  let errors = "";
  child.stderr.on("data", (chunk) => { errors += chunk.toString(); });
  const exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  try {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error(`Packaged API startup timed out: ${errors}`)), 10_000);
      const done = (error) => { clearTimeout(timeout); error ? reject(error) : resolve(); };
      child.stdout.on("data", (chunk) => {
        output += chunk.toString();
        if (output.includes(`trust-registry-api listening on ${origin}\n`)
          && output.includes("Fixture off-chain DID sign-in enabled")) done();
      });
      child.once("exit", (code) => done(new Error(`Packaged API exited before startup (${code}): ${errors}`)));
      child.once("error", done);
    });
  } catch (error) {
    if (child.exitCode === null) child.kill("SIGTERM");
    await exited;
    throw error;
  }
  return {
    origin,
    async stop() {
      if (child.exitCode === null) child.kill("SIGTERM");
      const result = await exited;
      assert.equal(result.code, 0, `Packaged API exited unexpectedly: ${errors}`);
    },
  };
}

test("packaged fixture host signs in off-chain DID in both portals without granting a role", async ({
  page, allowedLocalOrigins,
}) => {
  const directory = await mkdtemp(join(tmpdir(), "tr-packaged-offchain-browser-"));
  const workspacePath = join(directory, "workspace.json");
  const challengeStorePath = join(directory, "challenges.json");
  const portalRoot = join(directory, "portals");
  const port = await reserveLoopbackPort();
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const actorDid = createLongFormOffchainMidnightDIDString({
    version: 1, alsoKnownAs: [],
    verificationMethod: [{
      id: "./keys#auth",
      publicKeyJwk: { kty: KeyType.OKP, crv: CurveType.Ed25519, x: publicJwk.x },
      relationships: { authentication: true, assertionMethod: false, keyAgreement: false,
        capabilityInvocation: false, capabilityDelegation: false },
    }],
    service: [],
  });
  const actorKeyId = `${actorDid}/keys#auth`;
  let host;
  try {
    await writeWorkspaceToFile(workspacePath, createOperatorWorkspace({ label: "packaged-browser-auth" }));
    await mkdir(portalRoot);
    for (const role of ["admin", "applicant"]) {
      await cp(join("packages", `trust-registry-${role === "admin" ? "admin-console" : "applicant-portal"}`, "dist"),
        join(portalRoot, role), { recursive: true });
    }
    host = await startPackagedHost({ workspacePath, challengeStorePath, portalRoot, port });
    allowedLocalOrigins.add(host.origin);
    const governedWrites = [];
    page.on("request", (request) => {
      if (request.method() === "POST" && new URL(request.url()).pathname.startsWith("/v1/governed/")) {
        governedWrites.push(request.url());
      }
    });
    await page.exposeFunction("signTrustRegistryDigest", (digest) => ({
      keyId: actorKeyId, algorithm: "ed25519",
      value: `0x${signEd25519(null, Uint8Array.from(digest), privateKey).toString("hex")}`,
    }));
    await page.addInitScript(({ did, keyId }) => {
      window.midnightTrustRegistryDidSigner = {
        getIdentity: async () => ({ actorDid: did, actorKeyId: keyId }),
        signDigest: async ({ digest }) => window.signTrustRegistryDigest(Array.from(digest)),
      };
    }, { did: actorDid, keyId: actorKeyId });

    await page.goto(`${host.origin}/applicant/`);
    await expect(page.locator(".source-badge")).toHaveText("Practice workspace");
    await expect(page.locator("#my-applications")).toHaveCount(0);
    await expect(page.locator('a[href="#my-applications"]')).toHaveCount(0);
    await expect(page.locator(".journey-prerequisite")).toContainText("cannot register applications");
    await expect(page.locator('.task-nav a[href="#governed-requests"]'))
      .toContainText("Review membership requirements");
    await page.locator('.journey-cards a[href="#issuer-request"]').click();
    await expect(page.locator("#issuer-request [data-prepare-issuer]")).toBeDisabled();
    await expect(page.locator("#issuer-request [data-private-host-guide]"))
      .toContainText("no application registration service");
    await page.locator(".hero-sign-in").click();
    await page.getByRole("button", { name: "Sign in with digital identity" }).click();
    await expect(page.locator(".portal-profile-status")).toContainText(actorDid);
    await expect(page.locator(".application-readiness")).toContainText("Requires governed approval");
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.locator(".portal-profile-card")).toContainText("A digital identity signer is connected");

    await page.goto(`${host.origin}/admin/`);
    await page.getByRole("link", { name: "Workspace settings" }).first().click();
    await page.getByRole("button", { name: "Sign in with digital identity" }).click();
    await expect(page.locator(".portal-profile-status")).toContainText(actorDid);
    await expect(page.locator(".portal-profile-card")).toContainText("maintainer authority is checked separately");
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.locator(".portal-profile-card")).toContainText("A digital identity signer is connected");
    assert.deepEqual(governedWrites, []);
  } finally {
    if (host !== undefined) await host.stop();
    await rm(directory, { recursive: true, force: true });
  }
});
