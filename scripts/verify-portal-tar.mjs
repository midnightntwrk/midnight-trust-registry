import { createHash } from "node:crypto";

const BLOCK = 512;
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const SAFE_PATH = /^[A-Za-z0-9][A-Za-z0-9._/-]*\/?$/u;

function headerText(bytes) {
  const end = bytes.indexOf(0);
  return bytes.subarray(0, end < 0 ? bytes.length : end).toString("utf8");
}

function headerNumber(bytes) {
  const value = headerText(bytes).trim();
  if (!/^[0-7]+$/u.test(value)) throw new Error("Portal tar has an invalid octal header");
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed)) throw new Error("Portal tar has an oversized entry");
  return parsed;
}

export function portalTarLimit(expectedAssets) {
  const size = expectedAssets.reduce((total, asset) => total + asset.size + BLOCK * 2, 2 * 1024 * 1024);
  if (!Number.isSafeInteger(size) || size > MAX_ARCHIVE_BYTES) {
    throw new Error("Portal asset readback exceeds the bounded archive limit");
  }
  return size;
}

/** Parse Docker's bounded tar output without extracting names onto the host filesystem. */
export function verifyPortalTar(bytes, root, expectedAssets) {
  if (!Buffer.isBuffer(bytes) || bytes.length < BLOCK * 3 || bytes.length > MAX_ARCHIVE_BYTES
    || !["public", "portals"].includes(root)) {
    throw new Error("Portal tar is missing or oversized");
  }
  const expectedFiles = new Map(expectedAssets.map((asset) => [asset.path, asset]));
  if (expectedFiles.size !== expectedAssets.length
    || new Set(expectedAssets.map((asset) => asset.path.normalize("NFC").toLowerCase())).size
      !== expectedAssets.length) {
    throw new Error("Verified portal manifest contains duplicate or case-colliding paths");
  }
  const expectedDirectories = new Set([`${root}/`]);
  for (const asset of expectedAssets) {
    const parts = asset.path.split("/");
    for (let length = 1; length < parts.length; length += 1) {
      expectedDirectories.add(`${root}/${parts.slice(0, length).join("/")}/`);
    }
  }
  const seen = new Set();
  const folded = new Set();
  let offset = 0;
  let fileCount = 0;
  while (offset + BLOCK <= bytes.length) {
    const header = bytes.subarray(offset, offset + BLOCK);
    if (header.every((byte) => byte === 0)) {
      if (offset + BLOCK * 2 > bytes.length
        || bytes.subarray(offset).some((byte) => byte !== 0) || fileCount !== expectedFiles.size
        || seen.size !== expectedFiles.size + expectedDirectories.size) {
        throw new Error("Portal tar entries disagree with the verified asset list");
      }
      return fileCount;
    }
    const checksum = headerNumber(header.subarray(148, 156));
    if (headerText(header.subarray(257, 263)) !== "ustar") {
      throw new Error("Portal tar requires a ustar header");
    }
    let observedChecksum = 0;
    for (let index = 0; index < BLOCK; index += 1) {
      observedChecksum += index >= 148 && index < 156 ? 32 : header[index];
    }
    if (checksum !== observedChecksum) throw new Error("Portal tar header checksum disagrees");
    const prefix = headerText(header.subarray(345, 500));
    const name = headerText(header.subarray(0, 100));
    const path = prefix ? `${prefix}/${name}` : name;
    const type = header[156];
    const size = headerNumber(header.subarray(124, 136));
    const end = offset + BLOCK + size;
    if (!SAFE_PATH.test(path) || path.split("/").some((part, index, parts) =>
      part === "." || part === ".." || (part === "" && index !== parts.length - 1))
      || !path.startsWith(`${root}/`) || end > bytes.length) {
      throw new Error("Portal tar contains an unsafe path or entry size");
    }
    const key = path.normalize("NFC").toLowerCase();
    if (seen.has(path) || folded.has(key)) {
      throw new Error("Portal tar contains duplicate or case-colliding paths");
    }
    seen.add(path);
    folded.add(key);
    if (type === 53 && path.endsWith("/") && size === 0) {
      if (!expectedDirectories.has(path)) throw new Error("Portal tar contains an extra directory");
    } else if (type === 48 || type === 0) {
      const asset = expectedFiles.get(path.slice(root.length + 1));
      if (!asset || path.endsWith("/") || size !== asset.size
        || createHash("sha256").update(bytes.subarray(offset + BLOCK, end)).digest("hex") !== asset.sha256) {
        throw new Error("Portal tar assets disagree with the verified manifest");
      }
      fileCount += 1;
    } else {
      throw new Error("Portal tar contains a linked or unsupported entry");
    }
    offset += BLOCK + Math.ceil(size / BLOCK) * BLOCK;
  }
  throw new Error("Portal tar has no complete end marker");
}
