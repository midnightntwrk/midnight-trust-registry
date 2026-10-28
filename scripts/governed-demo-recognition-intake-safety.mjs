import { Buffer } from "node:buffer";
import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
} from "../contracts/trust-registry/dist/index.js";
import { sha256Hex } from "../packages/trust-registry-domain/dist/index.js";
import {
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  recognitionAuthorityAssertionDigest,
} from "../packages/trust-registry-integration/dist/index.js";

const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;

export async function runRecognitionIntakeSafetyScenarios(matrix, {
  verifyRecognitionChallenge,
  recognitionAssertion,
  recognitionStatement,
  recognitionAuthoritySeed,
  recognitionMethodId,
  recognitionAuthorityDid,
  recognitionAccreditationFixture,
  harness,
}) {
  await matrix.expectRejected(() => verifyRecognitionChallenge({
    ...recognitionAssertion,
    statement: { ...recognitionStatement, recognizedRegistryId: "registry:external:wrong:v1" },
  }), {
    id: "recognition-intake-wrong-registry-binding",
    invariant: "Recognition authority evidence must match the challenged external registry",
    boundary: "integration", messagePattern: /does not match/u,
    category: "recognition-registry-mismatch",
  });
  await matrix.expectRejected(() => verifyRecognitionChallenge({
    ...recognitionAssertion,
    proof: {
      ...recognitionAssertion.proof,
      signature: asHex(encodeJubjubSignature(signJubjubDigestFromSeed(
        recognitionAuthoritySeed,
        recognitionAuthorityAssertionDigest({
          ...recognitionStatement,
          scopeResourceId: "credential-family:wrong:v1",
        }, recognitionMethodId),
      ))),
    },
  }), {
    id: "recognition-intake-authority-signature-mismatch",
    invariant: "A scoped authority signature cannot be reused for another resource",
    boundary: "integration", messagePattern: /signature is invalid/u,
    category: "recognition-signature-mismatch",
  });
  await matrix.expectRejected(() => verifyRecognitionChallenge(recognitionAssertion, {
    readCurrentGovernance: async () => ({
      governancePolicy: harness.policyRecord,
      activePolicyCommitment: sha256Hex("stale-recognition-policy"),
    }),
  }), {
    id: "recognition-intake-governance-policy-drift",
    invariant: "Accreditation must resolve against the current governed policy commitment",
    boundary: "integration", messagePattern: /active governed policy/u,
    category: "recognition-policy-drift",
  });
  await matrix.expectRejected(() => verifyRecognitionChallenge(recognitionAssertion, {
    statusSource: {
      verifyPinnedStatus: async (request) => ({
        ...await recognitionAccreditationFixture.input.statusSource.verifyPinnedStatus(request),
        active: false,
      }),
    },
  }), {
    id: "recognition-intake-inactive-accreditation-status",
    invariant: "A non-active accreditation status cannot authorize recognition intake",
    boundary: "integration", messagePattern: /status is not active/u,
    category: "recognition-status-inactive",
  });
  await matrix.expectRejected(() => verifyRecognitionChallenge(recognitionAssertion, {
    accreditation: {
      ...recognitionAccreditationFixture.input.submission,
      rawCredentialBody: `${recognitionAccreditationFixture.input.submission.rawCredentialBody} `,
    },
  }), {
    id: "recognition-intake-accreditation-substitution",
    invariant: "The authority assertion must commit to the exact submitted accreditation VP",
    boundary: "integration", messagePattern: /submitted accreditation VP/u,
    category: "recognition-accreditation-substitution",
  });
  const rotatedRecognitionResolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(recognitionAuthorityDid, {
      schnorrJubjubAssertionMethods: [{
        id: "assertion-1",
        publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(117)),
      }],
    }),
  ]);
  await matrix.expectRejected(() => verifyRecognitionChallenge(recognitionAssertion, {
    resolver: rotatedRecognitionResolver,
  }), {
    id: "recognition-intake-rotated-authority-did-key",
    invariant: "An assertion signed by the previous DID key fails after the resolved assertion key rotates",
    boundary: "integration", messagePattern: /signature is invalid/u,
    category: "recognition-rotated-did-key",
  });
}
