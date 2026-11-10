import { createHash } from "node:crypto";
import { createReadStream, lstatSync, opendirSync, readlinkSync } from "node:fs";
import { join, relative, sep } from "node:path";

const MAX_ENTRIES = 500_000;

/** @param {string} path @param {import("node:fs").Stats} before */
async function fileHash(path, before) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  const after = lstatSync(path);
  if (!after.isFile() || after.nlink !== 1 || after.dev !== before.dev
    || after.ino !== before.ino || after.size !== before.size
    || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
    throw new Error(`Provider file changed while hashing: ${path}`);
  }
  return hash.digest("hex");
}

/** Content-only digest survives a reviewed ownership/permission transfer. */
/** @param {string} root */
export async function providerRuntimeContent(root) {
  /** @type {(string | number)[][]} */
  const entries = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    if (directory === undefined) throw new Error("Provider traversal lost a directory");
    const handle = opendirSync(directory);
    try {
      for (let item = handle.readSync(); item !== null; item = handle.readSync()) {
        if (entries.length >= MAX_ENTRIES) throw new Error("Provider content exceeds the bounded entry count");
        const path = join(directory, item.name);
        const name = relative(root, path).split(sep).join("/");
        if (name === "provider-stage.json") continue;
        const stat = lstatSync(path);
        if (stat.isDirectory()) {
          entries.push([name, "directory"]);
          pending.push(path);
        } else if (stat.isFile() && stat.nlink === 1) {
          entries.push([name, "file", stat.size, await fileHash(path, stat)]);
        } else if (stat.isSymbolicLink()) {
          entries.push([name, "link", readlinkSync(path)]);
        } else {
          throw new Error(`Provider content has a non-regular entry: ${name}`);
        }
      }
    } finally {
      handle.closeSync();
    }
  }
  entries.sort((left, right) => Buffer.compare(Buffer.from(String(left[0])), Buffer.from(String(right[0]))));
  const digest = createHash("sha256");
  digest.update("tr-provider-runtime-content-v1\n");
  for (const entry of entries) digest.update(`${JSON.stringify(entry)}\n`);
  return { format: "tr-provider-runtime-content-v1", sha256: digest.digest("hex"), entries: entries.length };
}
