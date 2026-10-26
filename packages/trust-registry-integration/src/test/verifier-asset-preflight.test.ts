import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { TrustRegistryContract, trustRegistryWitnesses } from "@midnight-ntwrk/trust-registry-contract";

import { readPinnedInstalledVerifierKey, verifyInstalledVerifierKeyAssets } from "../verifier-asset-preflight.js";

const directories: string[] = [];
const circuitNames = Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits);
const contents = (name: string) => Buffer.from(`verifier:${name}`);
const manifest = {
  format: "tr-release-candidate-manifest-v2" as const,
  verifierKeySha256: Object.fromEntries(circuitNames.map((name) => [
    name, createHash("sha256").update(contents(name)).digest("hex"),
  ])),
};

async function assets(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "tr-verifier-assets-"));
  directories.push(directory);
  const keys = join(directory, "keys");
  await mkdir(keys);
  await Promise.all(circuitNames.map((name) => writeFile(join(keys, `${name}.verifier`), contents(name))));
  return directory;
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("installed verifier-key preflight", () => {
  it("reads only catalog-pinned bytes for a selected insertion", async () => {
    const directory = await assets();
    const name = circuitNames[0]!;
    await expect(readPinnedInstalledVerifierKey(manifest, name, directory))
      .resolves.toEqual(new Uint8Array(contents(name)));
    await expect(readPinnedInstalledVerifierKey(manifest, "notInCatalog", directory))
      .rejects.toThrow(/not in the release catalog/u);
    const file = join(directory, "keys", `${name}.verifier`);
    await rm(file);
    await symlink(join(directory, "keys", `${circuitNames[1]!}.verifier`), file);
    await expect(readPinnedInstalledVerifierKey(manifest, name, directory)).rejects.toThrow();
  });

  it("accepts only the exact installed inventory and bytes", async () => {
    const directory = await assets();
    await expect(verifyInstalledVerifierKeyAssets(manifest, directory)).resolves.toBeUndefined();
    await writeFile(join(directory, "keys", `${circuitNames[0]!}.verifier`), "changed");
    await expect(verifyInstalledVerifierKeyAssets(manifest, directory)).rejects.toThrow(/disagrees/u);
  });

  it("rejects missing, extra, and symlinked verifier files", async () => {
    const directory = await assets();
    const key = join(directory, "keys", `${circuitNames[0]!}.verifier`);
    await rm(key);
    await expect(verifyInstalledVerifierKeyAssets(manifest, directory)).rejects.toThrow(/inventory/u);
    await symlink(join(directory, "keys", `${circuitNames[1]!}.verifier`), key);
    await expect(verifyInstalledVerifierKeyAssets(manifest, directory)).rejects.toThrow();
    await rm(key);
    await writeFile(key, contents(circuitNames[0]!));
    await writeFile(join(directory, "keys", "extra.verifier"), "extra");
    await expect(verifyInstalledVerifierKeyAssets(manifest, directory)).rejects.toThrow(/inventory/u);
  });

  it("rejects incomplete manifests before reading assets", async () => {
    const directory = await assets();
    await expect(verifyInstalledVerifierKeyAssets({
      ...manifest, verifierKeySha256: { [circuitNames[0]!]: manifest.verifierKeySha256[circuitNames[0]!]! },
    }, directory)).rejects.toThrow(/incomplete/u);
  });

  it("rejects a symlinked verifier-key directory", async () => {
    const directory = await assets();
    const replacement = await mkdtemp(join(tmpdir(), "tr-verifier-link-"));
    directories.push(replacement);
    await rm(join(directory, "keys"), { recursive: true });
    await symlink(replacement, join(directory, "keys"));
    await expect(verifyInstalledVerifierKeyAssets(manifest, directory)).rejects.toThrow(/directory/u);
  });
});
