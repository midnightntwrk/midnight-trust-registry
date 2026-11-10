import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

import { z } from "zod";

export const ScopedIdentifierSchema = z
  .string()
  .min(3)
  .regex(
    /^[a-z0-9][a-z0-9:._-]*$/i,
    "Scoped identifiers must use URL-safe punctuation only",
  );

export const DidSchema = z
  .string()
  .startsWith("did:", "DID values must start with did:")
  .min(7);

export const UriSchema = z.string().url();

export const HashHexSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/, "Expected a 32-byte hex value prefixed with 0x");

export function createScopedIdentifier(
  namespace: string,
  ...parts: string[]
): string {
  const normalizedNamespace = normalizeIdentifierPart(namespace, "namespace");
  const normalizedParts = parts.map((part, index) =>
    normalizeIdentifierPart(part, `part ${index + 1}`),
  );
  const scoped = [normalizedNamespace, ...normalizedParts].join(":");
  return ScopedIdentifierSchema.parse(scoped);
}

export function sha256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
  return `0x${bytesToHex(sha256(bytes))}`;
}

function normalizeIdentifierPart(value: string, label: string): string {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.length === 0) {
    throw new Error(`${label} must not be empty`);
  }

  const normalized = trimmed
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9:._-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-:.]+|[-:.]+$/g, "");

  if (normalized.length === 0) {
    throw new Error(`${label} did not produce a valid scoped identifier part`);
  }

  return normalized;
}
