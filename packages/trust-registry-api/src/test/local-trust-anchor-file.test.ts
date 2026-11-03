import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

import { readProtectedLocalTrustAnchor } from "../local-trust-anchor-file.js";

it("reads only a bounded, non-replaceable first-run anchor", async () => {
  const boundary = await mkdtemp(join(tmpdir(), "tr-api-anchor-"));
  const directory = join(boundary, "installed");
  const path = join(directory, "anchor.json");
  const options = { boundary, trustedUid: process.getuid!() };
  try {
    await mkdir(directory);
    await writeFile(path, "{\"format\":\"tr-local-api-trust-anchor-v1\"}\n", { mode: 0o444 });
    await chmod(directory, 0o555);
    await chmod(boundary, 0o555);
    await expect(readProtectedLocalTrustAnchor(path, options))
      .resolves.toEqual(Buffer.from("{\"format\":\"tr-local-api-trust-anchor-v1\"}\n"));
    await chmod(directory, 0o775);
    await expect(readProtectedLocalTrustAnchor(path, options))
      .rejects.toThrow(/unsafe ancestor/u);
    await chmod(directory, 0o555);
    await chmod(path, 0o666);
    await expect(readProtectedLocalTrustAnchor(path, options))
      .rejects.toThrow(/protected regular file/u);
    await chmod(path, 0o444);
    await chmod(directory, 0o755);
    await link(path, join(directory, "hardlink.json"));
    await chmod(directory, 0o555);
    await expect(readProtectedLocalTrustAnchor(path, options))
      .rejects.toThrow(/protected regular file/u);
    await chmod(directory, 0o755);
    await rm(join(directory, "hardlink.json"));
    await symlink(path, join(directory, "alias.json"));
    await chmod(directory, 0o555);
    await expect(readProtectedLocalTrustAnchor(join(directory, "alias.json"), options))
      .rejects.toThrow();
    await expect(readProtectedLocalTrustAnchor(join(boundary, "../outside.json"), options))
      .rejects.toThrow(/outside its protected boundary/u);
  } finally {
    await chmod(directory, 0o755).catch(() => {});
    await chmod(boundary, 0o755).catch(() => {});
    await rm(boundary, { recursive: true, force: true });
  }
});
