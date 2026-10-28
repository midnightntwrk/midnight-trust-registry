/**
 * @param {Buffer} bytes
 * @param {string} label
 * @returns {unknown}
 */
export function parseCanonicalSignedJson(bytes, label) {
  const raw = bytes.toString("utf8");
  /** @type {unknown} */
  const value = JSON.parse(raw);
  if (!Buffer.from(raw, "utf8").equals(bytes)
    || (raw !== JSON.stringify(value) && raw !== `${JSON.stringify(value, null, 2)}\n`)) {
    throw new Error(`${label} must use canonical signed JSON without duplicate keys`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {readonly string[]} fields
 * @returns {boolean}
 */
export function exactFields(value, fields) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join("\0") === [...fields].sort().join("\0");
}
