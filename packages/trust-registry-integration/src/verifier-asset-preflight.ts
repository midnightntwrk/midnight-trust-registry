import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { TrustRegistryContract, trustRegistryWitnesses } from "@midnight-ntwrk/trust-registry-contract";

import type { ReleaseVerifierKeyManifest } from "./public-network-deployment.js";

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
    || Object.keys(expected).sort().join("\0") !== circuitNames.join("\0")
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
  if (actualNames.join("\0") !== circuitNames.join("\0")) {
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
