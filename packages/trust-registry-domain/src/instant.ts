const RFC3339_INSTANT = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;

const parseInstant = (value: string): { second: number; fraction: string } => {
  const match = RFC3339_INSTANT.exec(value);
  if (match === null) throw new Error(`invalid timestamp: ${value}`);
  const second = Date.parse(`${match[1]}${match[3]}`);
  if (!Number.isFinite(second)) throw new Error(`invalid timestamp: ${value}`);
  return { second, fraction: match[2] ?? "" };
};

const compareFractions = (left: string, right: string): number => {
  const width = Math.max(left.length, right.length);
  const a = left.padEnd(width, "0");
  const b = right.padEnd(width, "0");
  return a === b ? 0 : a < b ? -1 : 1;
};

/** Compare RFC3339 instants without discarding digits beyond milliseconds. */
export const compareRfc3339Instants = (left: string, right: string): number => {
  const a = parseInstant(left);
  const b = parseInstant(right);
  if (a.second !== b.second) return a.second < b.second ? -1 : 1;
  return compareFractions(a.fraction, b.fraction);
};

/** Bound a duration in whole seconds without rounding either instant to milliseconds. */
export const isRfc3339DurationWithinSeconds = (
  start: string, end: string, maximumSeconds: number,
): boolean => {
  if (!Number.isSafeInteger(maximumSeconds) || maximumSeconds < 0
    || !Number.isSafeInteger(maximumSeconds * 1000)) {
    throw new Error("maximumSeconds must be a nonnegative safe integer");
  }
  const a = parseInstant(start);
  const b = parseInstant(end);
  const wholeSecondDeltaMs = b.second - a.second;
  if (wholeSecondDeltaMs < 0
    || (wholeSecondDeltaMs === 0 && compareFractions(b.fraction, a.fraction) < 0)) return false;
  const maximumMs = maximumSeconds * 1000;
  if (wholeSecondDeltaMs !== maximumMs) return wholeSecondDeltaMs < maximumMs;
  return compareFractions(b.fraction, a.fraction) <= 0;
};
