/** Compare JSON object field names without delimiter-joining attacker-controlled keys. */
export const hasExactFieldNames = (
  value: Record<string, unknown>,
  fields: readonly string[],
): boolean => {
  const keys = Object.keys(value);
  const expected = new Set(fields);
  return keys.length === expected.size && expected.size === fields.length
    && keys.every((key) => expected.has(key));
};
