import { execFileSync } from "node:child_process";
import { lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const REVISION = /^[0-9a-f]{40}$/u;
const SCRIPTS = ["materialize-standalone-proof-params.mjs",
  "standalone-proof-parameter-catalog.mjs"];

/** Copy only signed Git blobs into a private mount, never live checkout bytes.
 * @param {string} sourceRoot
 * @param {string} revision
 * @param {string} privateRoot
 * @param {typeof execFileSync} [run]
 */
export async function signedKeygenScriptSnapshot(sourceRoot, revision, privateRoot,
  run = execFileSync) {
  if (!REVISION.test(revision)) throw new Error("Signed keygen source revision is malformed");
  const root = resolve(privateRoot);
  const stat = await lstat(root);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Keygen script snapshot requires an owned private setup directory");
  }
  const cwd = resolve(sourceRoot);
  run("git", ["verify-commit", revision], { cwd, stdio: ["ignore", "pipe", "pipe"] });
  const stage = await mkdtemp(join(root, ".tr-keygen-scripts-"));
  try {
    for (const name of SCRIPTS) {
      const bytes = run("git", ["show", `${revision}:scripts/${name}`],
        { cwd, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1024 * 1024 });
      if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 1024 * 1024) {
        throw new Error(`Signed keygen script is missing or oversized: ${name}`);
      }
      await writeFile(join(stage, name), bytes, { flag: "wx", mode: 0o400 });
    }
    return stage;
  } catch (error) {
    await rm(stage, { recursive: true });
    throw error;
  }
}
