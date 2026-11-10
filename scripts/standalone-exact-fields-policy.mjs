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

/**
 * @param {unknown} value
 * @param {readonly string[]} fields
 * @returns {value is Record<string, unknown>}
 */
export function exactRecordFields(value, fields) {
  return exactFields(value, fields);
}

/**
 * @param {unknown} value
 * @param {readonly string[]} names
 * @returns {value is string[]}
 */
export function exactStringSet(value, names) {
  if (!Array.isArray(value)) return false;
  const expected = new Set(names);
  return value.length === expected.size && new Set(value).size === expected.size
    && expected.size === names.length
    && value.every((name) => typeof name === "string" && expected.has(name));
}
