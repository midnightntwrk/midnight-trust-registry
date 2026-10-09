import { sha256Hex } from "./ids.js";

export function canonicalizeJson(value: unknown): string {
  return canonicalize(value, new WeakSet<object>());
}

function canonicalize(value: unknown, ancestors: WeakSet<object>): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot contain non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError("Canonical JSON cannot contain cycles");
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        throw new TypeError("Canonical JSON cannot contain sparse arrays");
      }
    }
    if (Reflect.ownKeys(value).some((key) => {
      if (key === "length") return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key)
        || Number(key) >= value.length || descriptor === undefined || !("value" in descriptor);
    })) {
      throw new TypeError("Canonical JSON arrays require dense data properties only");
    }
    ancestors.add(value);
    try {
      return `[${value.map((item) => canonicalize(item, ancestors)).join(",")}]`;
    } finally {
      ancestors.delete(value);
    }
  }
  if (typeof value === "object") {
    if (ancestors.has(value)) throw new TypeError("Canonical JSON cannot contain cycles");
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Canonical JSON requires plain objects");
    }
    const record = value as Record<string, unknown>;
    const keys = Reflect.ownKeys(record);
    if (keys.some((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      return typeof key !== "string" || descriptor?.enumerable !== true
        || descriptor === undefined || !("value" in descriptor);
    })) {
      throw new TypeError("Canonical JSON requires enumerable data properties only");
    }
    ancestors.add(value);
    try {
      return `{${(keys as string[]).sort().map((key) =>
        `${JSON.stringify(key)}:${canonicalize(record[key], ancestors)}`).join(",")}}`;
    } finally {
      ancestors.delete(value);
    }
  }
  throw new TypeError("Canonical JSON must contain JSON values only");
}

export function computeMutationPayloadCommitment(validatedPayload: unknown): string {
  return sha256Hex(JSON.stringify([
    "tr:mutation:payload:v1",
    canonicalizeJson(validatedPayload),
  ]));
}
