import { Buffer } from "node:buffer";

import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";

const DEFAULT_BASE_TIMESTAMP_MS = Date.parse("2026-05-20T00:00:00Z");

export type SequenceToTimestamp = (sequence: bigint) => string;

export const bytes32Commitment = (value: string): Uint8Array =>
  Buffer.from(sha256Hex(value).slice(2), "hex");

export const bytes32Hex = (value: Uint8Array): string =>
  `0x${Buffer.from(value).toString("hex")}`;

export const hashHexToBytes32 = (value: string): Uint8Array =>
  Buffer.from(value.replace(/^0x/, ""), "hex");

export const defaultSequenceToTimestamp: SequenceToTimestamp = (
  sequence: bigint,
): string =>
  new Date(DEFAULT_BASE_TIMESTAMP_MS + Number(sequence) * 60_000).toISOString();

export const sameBytes32 = (
  left: Uint8Array,
  right: Uint8Array,
): boolean => Buffer.from(left).equals(Buffer.from(right));
