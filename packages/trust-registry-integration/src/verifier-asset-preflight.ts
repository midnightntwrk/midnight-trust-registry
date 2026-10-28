import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { TrustRegistryContract, trustRegistryWitnesses } from "@midnight-ntwrk/trust-registry-contract";

import type { ReleaseVerifierKeyManifest } from "./public-network-deployment.js";
import { hasExactFieldNames } from "./exact-field-names.js";

const installedAssetsPath = resolve(
  dirname(fileURLToPath(import.meta.resolve("@midnight-ntwrk/trust-registry-contract/contract"))),
  "managed/trust-registry",
);

/** Checks the installed verifier files before an irreversible deployment attempt. */
export async function verifyInstalledVerifierKeyAssets(
  manifest: ReleaseVerifierKeyManifest,
  assetsPath = installedAssetsPath,
): Promise<void> {
  const expected = manifest?.verifierKeySha256;
  const circuitNames = Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits).sort();
  if (manifest?.format !== "tr-release-candidate-manifest-v2"
    || expected === null || typeof expected !== "object" || Array.isArray(expected)
    || !hasExactFieldNames(expected, circuitNames)
    || circuitNames.some((name) => !/^[0-9a-f]{64}$/u.test(expected[name] ?? ""))) {
    throw new Error("Release manifest has an invalid or incomplete verifier-key catalog");
  }

  const keysPath = join(assetsPath, "keys");
  if (!(await lstat(keysPath)).isDirectory()) {
    throw new Error("Installed verifier-key directory must not be a symlink");
  }
  const actualNames = (await readdir(keysPath))
    .filter((name) => name.endsWith(".verifier"))
    .map((name) => name.slice(0, -".verifier".length)).sort();
  if (actualNames.length !== circuitNames.length
    || actualNames.some((name, index) => name !== circuitNames[index])) {
    throw new Error("Installed verifier-key inventory disagrees with the release manifest");
  }
  for (const name of circuitNames) {
    const handle = await open(join(keysPath, `${name}.verifier`), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size === 0 || stat.size > 16 * 1024 * 1024) {
        throw new Error(`Installed verifier key is not a bounded regular file: ${name}`);
      }
      const hash = createHash("sha256").update(await handle.readFile()).digest("hex");
      if (hash !== expected[name]) {
        throw new Error(`Installed verifier key disagrees with the release manifest: ${name}`);
      }
    } finally {
      await handle.close();
    }
  }
}

/** Rechecks the selected bytes after catalog preflight so the submitted key matches its pin. */
export async function readPinnedInstalledVerifierKey(
  manifest: ReleaseVerifierKeyManifest,
  name: string,
  assetsPath = installedAssetsPath,
): Promise<Uint8Array> {
  await verifyInstalledVerifierKeyAssets(manifest, assetsPath);
  if (!Object.hasOwn(manifest.verifierKeySha256, name)) {
    throw new Error("Selected verifier key is not in the release catalog");
  }
  const handle = await open(join(assetsPath, "keys", `${name}.verifier`), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size === 0 || stat.size > 16 * 1024 * 1024) {
      throw new Error("Selected verifier key is not a bounded regular file");
    }
    const bytes = new Uint8Array(await handle.readFile());
    if (createHash("sha256").update(bytes).digest("hex") !== manifest.verifierKeySha256[name]) {
      throw new Error("Selected verifier key changed after catalog preflight");
    }
    return bytes;
  } finally {
    await handle.close();
  }
}
