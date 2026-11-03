import { createHash } from "node:crypto";
import { closeSync, constants, copyFileSync, mkdirSync, openSync, readSync, statSync } from "node:fs";
import { basename, join } from "node:path";

const sha256 = (path) => {
  const hash = createHash("sha256");
  const fd = openSync(path, "r");
  try {
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let length;
    while ((length = readSync(fd, chunk, 0, chunk.length, null)) > 0) {
      hash.update(chunk.subarray(0, length));
    }
    return hash.digest("hex");
  } finally {
    closeSync(fd);
  }
};

export function snapshotReleaseTarballs(manifest, artifactDir, destinationDir) {
  if (!Array.isArray(manifest?.packages) || manifest.packages.length === 0) {
    throw new Error("Release snapshot requires a verified package manifest");
  }
  mkdirSync(destinationDir, { mode: 0o700 });
  return manifest.packages.map(({ filename, sha256: expectedHash, sizeBytes }) => {
    if (typeof filename !== "string" || filename !== basename(filename)) {
      throw new Error("Release snapshot package filename is invalid");
    }
    const target = join(destinationDir, filename);
    copyFileSync(join(artifactDir, filename), target,
      constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE);
    if (statSync(target).size !== sizeBytes || sha256(target) !== expectedHash) {
      throw new Error(`Release snapshot differs from verified package: ${filename}`);
    }
    return target;
  });
}
