import { sha256Hex } from "./ids.js";

const MAX_CANONICAL_JSON_LENGTH = 16 * 1024 * 1024;

const bounded = (serialized: string): string => {
  if (serialized.length > MAX_CANONICAL_JSON_LENGTH) {
    throw new TypeError("Canonical JSON exceeds the maximum length");
  }
  return serialized;
};

const joinBounded = (parts: readonly string[], prefix: string, suffix: string): string => {
  const length = parts.reduce((sum, part) => sum + part.length, prefix.length + suffix.length + Math.max(0, parts.length - 1));
  if (length > MAX_CANONICAL_JSON_LENGTH) {
    throw new TypeError("Canonical JSON exceeds the maximum length");
  }
  return `${prefix}${parts.join(",")}${suffix}`;
};

export function canonicalizeJson(value: unknown): string {
  return canonicalize(value, new WeakSet<object>(), new WeakMap<object, string>());
}

function canonicalize(value: unknown, ancestors: WeakSet<object>, memo: WeakMap<object, string>): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    if (typeof value === "string" && value.length > MAX_CANONICAL_JSON_LENGTH) {
      throw new TypeError("Canonical JSON exceeds the maximum length");
    }
    return bounded(JSON.stringify(value));
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot contain non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError("Canonical JSON cannot contain cycles");
    const cached = memo.get(value);
    if (cached !== undefined) return cached;
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (lengthDescriptor === undefined || !("value" in lengthDescriptor)
      || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0
      || lengthDescriptor.value > MAX_CANONICAL_JSON_LENGTH) {
      throw new TypeError("Canonical JSON requires bounded arrays");
    }
    const length = lengthDescriptor.value as number;
    if (Reflect.ownKeys(value).some((key) => {
      if (key === "length") return false;
      return typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key)
        || Number(key) >= length;
    })) {
      throw new TypeError("Canonical JSON arrays require dense data properties only");
    }
    ancestors.add(value);
    try {
      const parts: string[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, index);
        if (descriptor === undefined || !("value" in descriptor)) {
          throw new TypeError("Canonical JSON arrays require dense data properties only");
        }
        parts.push(canonicalize(descriptor.value, ancestors, memo));
      }
      const serialized = joinBounded(parts, "[", "]");
      memo.set(value, serialized);
      return serialized;
    } finally {
      ancestors.delete(value);
    }
  }
  if (typeof value === "object") {
    if (ancestors.has(value)) throw new TypeError("Canonical JSON cannot contain cycles");
    const cached = memo.get(value);
    if (cached !== undefined) return cached;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Canonical JSON requires plain objects");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length > MAX_CANONICAL_JSON_LENGTH || keys.some((key) => typeof key !== "string")) {
      throw new TypeError("Canonical JSON requires bounded string keys only");
    }
    ancestors.add(value);
    try {
      const parts = (keys as string[]).sort().map((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || descriptor.enumerable !== true || !("value" in descriptor)) {
          throw new TypeError("Canonical JSON requires enumerable data properties only");
        }
        return bounded(`${bounded(JSON.stringify(key))}:${canonicalize(descriptor.value, ancestors, memo)}`);
      });
      const serialized = joinBounded(parts, "{", "}");
      memo.set(value, serialized);
      return serialized;
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
