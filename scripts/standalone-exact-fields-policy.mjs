/**
 * @param {unknown} value
 * @param {readonly string[]} fields
 * @returns {boolean}
 */
export function exactFields(value, fields) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  const expected = new Set(fields);
  return keys.length === expected.size && expected.size === fields.length
    && keys.every((key) => expected.has(key));
}
