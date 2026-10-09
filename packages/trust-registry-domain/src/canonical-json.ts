import { sha256Hex } from "./ids.js";

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot contain non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalizeJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("Canonical JSON must contain JSON values only");
}

export function computeMutationPayloadCommitment(validatedPayload: unknown): string {
  return sha256Hex(JSON.stringify([
    "tr:mutation:payload:v1",
    canonicalizeJson(validatedPayload),
  ]));
}
