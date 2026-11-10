import { Buffer } from "node:buffer";

import type { Proof } from "@midnight-ntwrk/credential-compact";

type JsonRecord = Record<string, unknown>;

const record = (value: unknown, keys: readonly string[]): JsonRecord => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Application VP proof must be an object");
  }
  const result = value as JsonRecord;
  if (Object.keys(result).length !== keys.length || keys.some((key) => !Object.hasOwn(result, key))) {
    throw new TypeError("Application VP proof has unexpected fields");
  }
  return result;
};

const decimal = (value: unknown): bigint => {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/u.test(value)) {
    throw new TypeError("Application VP proof scalar is not canonical");
  }
  return BigInt(value);
};

const bytes32 = (value: unknown): Uint8Array => {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError("Application VP proof bytes are not canonical");
  }
  return Uint8Array.from(Buffer.from(value.slice(2), "hex"));
};

const point = (value: unknown): Proof["publicKey"] => {
  const fields = record(value, ["x", "y"]);
  return { x: decimal(fields.x), y: decimal(fields.y) };
};

const hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new RangeError("Application VP proof bytes must be 32 bytes");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export const encodeApplicationVpProof = (proof: Proof): JsonRecord => ({
  signerVerificationMethodRef: {
    controllerAddress: hex(proof.signerVerificationMethodRef.controllerAddress.bytes),
    methodId: hex(proof.signerVerificationMethodRef.methodId),
  },
  createdAt: proof.createdAt.toString(),
  challengeHash: hex(proof.challengeHash),
  publicKey: { x: proof.publicKey.x.toString(), y: proof.publicKey.y.toString() },
  signature: {
    r: { x: proof.signature.r.x.toString(), y: proof.signature.r.y.toString() },
    s: proof.signature.s.toString(),
  },
});

export const decodeApplicationVpProof = (value: unknown): Proof => {
  const proof = record(value, [
    "signerVerificationMethodRef", "createdAt", "challengeHash", "publicKey", "signature",
  ]);
  const method = record(proof.signerVerificationMethodRef, ["controllerAddress", "methodId"]);
  const signature = record(proof.signature, ["r", "s"]);
  const createdAt = decimal(proof.createdAt);
  if (createdAt > 18_446_744_073_709_551_615n) {
    throw new RangeError("Application VP proof timestamp exceeds Uint64");
  }
  return {
    signerVerificationMethodRef: {
      controllerAddress: { bytes: bytes32(method.controllerAddress) },
      methodId: bytes32(method.methodId),
    },
    createdAt,
    challengeHash: bytes32(proof.challengeHash),
    publicKey: point(proof.publicKey),
    signature: { r: point(signature.r), s: decimal(signature.s) },
  };
};
