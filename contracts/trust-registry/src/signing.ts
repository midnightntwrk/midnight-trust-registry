import { createHash, randomBytes } from "node:crypto";

import {
  ecAdd,
  ecMul,
  ecMulGenerator,
  type JubjubPoint,
} from "@midnight-ntwrk/compact-runtime";

import { pureCircuits } from "./managed/trust-registry/contract/index.js";

export type TrustRegistryActionDigest = [bigint, bigint, bigint, bigint];

export type TrustRegistryJubjubSignature = {
  announcement: JubjubPoint;
  response: bigint;
};

export const JUBJUB_ORDER =
  6554484396890773809930967563523245729705921265872317281365359162392183254199n;
export const TWO_248 =
  452312848583266388373324160190187140051835877600158453279131187530910662656n;
export const JUBJUB_SIGNATURE_LENGTH_BYTES = 96;

const bigintTo32Be = (value: bigint): Buffer => {
  const hex = value.toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
};

const bufferToBigint = (value: Uint8Array): bigint => {
  const buffer = Buffer.from(value);
  return buffer.length === 0 ? 0n : BigInt(`0x${buffer.toString("hex")}`);
};

const ensure32Bytes = (value: Uint8Array): Buffer => {
  const buffer = Buffer.from(value);
  if (buffer.length === 32) return buffer;
  if (buffer.length > 32) return buffer.subarray(0, 32);
  return Buffer.concat([buffer, Buffer.alloc(32 - buffer.length)]);
};

const serializeDigest = (digest: TrustRegistryActionDigest): Buffer =>
  Buffer.concat(digest.map((part) => bigintTo32Be(part)));

const hashToScalar = (input: Uint8Array): bigint =>
  bufferToBigint(createHash("sha256").update(input).digest()) % JUBJUB_ORDER;

export const normalizeScalar = (value: bigint): bigint =>
  ((value % JUBJUB_ORDER) + JUBJUB_ORDER) % JUBJUB_ORDER;

export const seedBytesToJubjubSecretScalar = (seedBytes: Uint8Array): bigint =>
  hashToScalar(ensure32Bytes(seedBytes));

export const deriveJubjubPublicKey = (secretScalar: bigint): JubjubPoint =>
  ecMulGenerator(normalizeScalar(secretScalar));

export const deriveJubjubPublicKeyFromSeed = (
  seedBytes: Uint8Array,
): JubjubPoint => deriveJubjubPublicKey(seedBytesToJubjubSecretScalar(seedBytes));

export const encodeJubjubSignature = (
  signature: TrustRegistryJubjubSignature,
): Uint8Array =>
  Buffer.concat([
    bigintTo32Be(signature.announcement.x),
    bigintTo32Be(signature.announcement.y),
    bigintTo32Be(signature.response),
  ]);

export const decodeJubjubSignature = (
  signature: Uint8Array,
): TrustRegistryJubjubSignature => {
  if (signature.length !== JUBJUB_SIGNATURE_LENGTH_BYTES) {
    throw new Error(
      `Jubjub signature must be exactly ${JUBJUB_SIGNATURE_LENGTH_BYTES} bytes`,
    );
  }
  return {
    announcement: {
      x: bufferToBigint(signature.subarray(0, 32)),
      y: bufferToBigint(signature.subarray(32, 64)),
    },
    response: bufferToBigint(signature.subarray(64, 96)),
  };
};

export const computeMaintainerActionDigest = (
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): TrustRegistryActionDigest =>
  pureCircuits.maintainerActionDigest(
    ensure32Bytes(registryId),
    ensure32Bytes(actionKind),
    ensure32Bytes(actionPayloadHash),
    actionSequence,
  ) as TrustRegistryActionDigest;

export const computeJubjubDigestChallenge = (
  announcement: JubjubPoint,
  publicKey: JubjubPoint,
  digest: TrustRegistryActionDigest,
): bigint =>
  pureCircuits.schnorrChallengeDigest(
    announcement.x,
    announcement.y,
    publicKey.x,
    publicKey.y,
    digest,
  ) % TWO_248;

export const signMaintainerActionDigest = (
  secretScalar: bigint,
  digest: TrustRegistryActionDigest,
  nonceSeed?: Uint8Array,
): TrustRegistryJubjubSignature => {
  const normalizedSecret = normalizeScalar(secretScalar);
  const publicKey = deriveJubjubPublicKey(normalizedSecret);
  const seedMaterial =
    nonceSeed ??
    Buffer.concat([
      bigintTo32Be(normalizedSecret),
      randomBytes(32),
      serializeDigest(digest),
    ]);
  const nonce = hashToScalar(seedMaterial);
  const announcement = ecMulGenerator(nonce);
  const challenge = computeJubjubDigestChallenge(
    announcement,
    publicKey,
    digest,
  );
  const response = normalizeScalar(nonce + challenge * normalizedSecret);
  return { announcement, response };
};

export const signMaintainerActionDigestFromSeed = (
  seedBytes: Uint8Array,
  digest: TrustRegistryActionDigest,
): TrustRegistryJubjubSignature => {
  const normalizedSeed = ensure32Bytes(seedBytes);
  return signMaintainerActionDigest(
    seedBytesToJubjubSecretScalar(normalizedSeed),
    digest,
    Buffer.concat([
      Buffer.from("midnight:tr:jubjub-schnorr:v1"),
      normalizedSeed,
      serializeDigest(digest),
    ]),
  );
};

export const signMaintainerActionFromSeed = (
  seedBytes: Uint8Array,
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): TrustRegistryJubjubSignature =>
  signMaintainerActionDigestFromSeed(
    seedBytes,
    computeMaintainerActionDigest(
      registryId,
      actionKind,
      actionPayloadHash,
      actionSequence,
    ),
  );

export const verifyMaintainerActionDigest = (
  publicKey: JubjubPoint,
  digest: TrustRegistryActionDigest,
  signature: TrustRegistryJubjubSignature,
): boolean => {
  const challenge = computeJubjubDigestChallenge(
    signature.announcement,
    publicKey,
    digest,
  );
  const lhs = ecMulGenerator(normalizeScalar(signature.response));
  const rhs = ecAdd(signature.announcement, ecMul(publicKey, challenge));
  return lhs.x === rhs.x && lhs.y === rhs.y;
};

export const verifyMaintainerAction = (
  publicKey: JubjubPoint,
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
  signature: TrustRegistryJubjubSignature,
): boolean =>
  verifyMaintainerActionDigest(
    publicKey,
    computeMaintainerActionDigest(
      registryId,
      actionKind,
      actionPayloadHash,
      actionSequence,
    ),
    signature,
  );
