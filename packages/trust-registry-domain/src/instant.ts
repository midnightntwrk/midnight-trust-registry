const RFC3339_INSTANT = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;

const parseInstant = (value: string): { second: number; fraction: string } => {
  const match = RFC3339_INSTANT.exec(value);
  if (match === null) throw new Error(`invalid timestamp: ${value}`);
  const second = Date.parse(`${match[1]}${match[3]}`);
  if (!Number.isFinite(second)) throw new Error(`invalid timestamp: ${value}`);
  return { second, fraction: match[2] ?? "" };
};

/** Compare RFC3339 instants without discarding digits beyond milliseconds. */
export const compareRfc3339Instants = (left: string, right: string): number => {
  const a = parseInstant(left);
  const b = parseInstant(right);
  if (a.second !== b.second) return a.second < b.second ? -1 : 1;
  const width = Math.max(a.fraction.length, b.fraction.length);
  const aFraction = a.fraction.padEnd(width, "0");
  const bFraction = b.fraction.padEnd(width, "0");
  return aFraction === bFraction ? 0 : aFraction < bFraction ? -1 : 1;
};
