import { parseArgs } from "node:util";

import { completeActorDidSignIn, listApplicantApplications, reconcileApplicantApplication,
  registerApplicantApplication, requestActorDidChallenge, signOutActorDid } from "@midnightntwrk/trust-registry-client/browser-authentication";
import { actorAuthenticationDigestBytes, ActorAuthenticationChallengeSchema,
  ActorAuthenticationSignatureSchema, SignedPendingApplicationSchema } from "@midnightntwrk/trust-registry-domain/browser";
import { z } from "zod";

import { serializeJson } from "./model.js";

const MAX_INPUT_BYTES = 128 * 1024;

const ActorSessionSchema = z.strictObject({
  actorDid: z.string().startsWith("did:midnight:"),
  actorKeyId: z.string().min(1),
  purpose: z.enum(["applicant-session", "maintainer-session"]),
  origin: z.string().url(),
  registryId: z.string().min(1),
  genesisHash: z.string().regex(/^0x[0-9a-f]{64}$/u),
  contractAddress: z.string().regex(/^0x[0-9a-f]{64}$/u),
  accessToken: z.string().regex(/^trsa_[A-Za-z0-9_-]{43}$/u),
  expiresAt: z.string().datetime({ offset: true }),
});

const ApplicantSessionSchema = ActorSessionSchema.extend({ purpose: z.literal("applicant-session") });
const DidContextSchema = ActorSessionSchema.pick({
  actorDid: true, actorKeyId: true, purpose: true, origin: true, registryId: true,
  genesisHash: true, contractAddress: true,
});
const SignedChallengeInputSchema = z.strictObject({
  expected: DidContextSchema,
  challenge: ActorAuthenticationChallengeSchema,
  signature: ActorAuthenticationSignatureSchema,
});

const ApplicantInputSchema = z.strictObject({
  session: ApplicantSessionSchema,
  request: SignedPendingApplicationSchema.optional(),
});

type ActorCliIo = {
  stdout: (value: string) => void;
  readStdin?: () => Promise<string>;
};

async function readInput(io: ActorCliIo): Promise<string> {
  if (io.readStdin !== undefined) {
    const value = await io.readStdin();
    if (Buffer.byteLength(value) > MAX_INPUT_BYTES) throw new Error("actor API input exceeds 128 KiB");
    return value;
  }
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    bytes += buffer.length;
    if (bytes > MAX_INPUT_BYTES) throw new Error("actor API input exceeds 128 KiB");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readActorCommand(argv: readonly string[], io: ActorCliIo) {
  const parsed = parseArgs({
    args: [...argv], allowPositionals: false, strict: true,
    options: { "api-base": { type: "string" } },
  });
  const apiBase = parsed.values["api-base"];
  if (typeof apiBase !== "string" || apiBase.length === 0) throw new Error("--api-base is required");
  const stdin = await readInput(io);
  let raw: unknown;
  try {
    raw = JSON.parse(stdin) as unknown;
  } catch {
    throw new Error("actor API stdin must contain one JSON object");
  }
  return { apiBase, raw };
}

/** The signer is external. The challenge and session are transferred over stdin/stdout, not argv. */
export async function runActorDidCommand(
  command: "api-did-challenge" | "api-did-sign-in" | "api-did-sign-out",
  argv: readonly string[],
  io: ActorCliIo,
): Promise<number> {
  const { apiBase, raw } = await readActorCommand(argv, io);
  if (command === "api-did-sign-out") {
    const session = ActorSessionSchema.safeParse(raw);
    if (!session.success) throw new Error("DID sign-out stdin must contain an identity session");
    await signOutActorDid({ apiBase, pageOrigin: session.data.origin, session: session.data });
    io.stdout(serializeJson({ status: "signed-out" }));
    return 0;
  }
  const context = (expected: z.infer<typeof DidContextSchema>) => ({
    apiBase, pageOrigin: expected.origin, registryId: expected.registryId, purpose: expected.purpose,
    actorDid: expected.actorDid, actorKeyId: expected.actorKeyId,
    deploymentIdentity: { expectedGenesisHash: expected.genesisHash, contractAddress: expected.contractAddress },
  });
  if (command === "api-did-challenge") {
    const input = DidContextSchema.safeParse(raw);
    if (!input.success) throw new Error("DID challenge stdin must contain an independently pinned actor context");
    const challenge = await requestActorDidChallenge(context(input.data));
    io.stdout(serializeJson({ challenge, digest: `0x${Buffer.from(actorAuthenticationDigestBytes(challenge)).toString("hex")}` }));
    return 0;
  }
  const input = SignedChallengeInputSchema.safeParse(raw);
  if (!input.success) throw new Error("DID sign-in stdin must contain the pinned context, challenge, and external signature");
  io.stdout(serializeJson(await completeActorDidSignIn({
    ...context(input.data.expected), challenge: input.data.challenge, signature: input.data.signature,
  })));
  return 0;
}

/** A caller supplies an ephemeral session and signed intent; the CLI never handles a private key. */
export async function runActorApiCommand(
  command: "api-register" | "api-reconcile" | "api-applications",
  argv: readonly string[],
  io: ActorCliIo,
): Promise<number> {
  const { apiBase, raw } = await readActorCommand(argv, io);
  const input = ApplicantInputSchema.safeParse(raw);
  if (!input.success) throw new Error("actor API stdin contains an invalid applicant session or signed request");
  const pageOrigin = input.data.session.origin;
  if (command === "api-register") {
    if (input.data.request === undefined) throw new Error("api-register requires a signed request on stdin");
    io.stdout(serializeJson(await registerApplicantApplication({
      apiBase, pageOrigin, session: input.data.session, request: input.data.request,
    })));
    return 0;
  }
  if (command === "api-reconcile") {
    if (input.data.request === undefined) throw new Error("api-reconcile requires the original signed request on stdin");
    io.stdout(serializeJson(await reconcileApplicantApplication({
      apiBase, pageOrigin, session: input.data.session, request: input.data.request,
    })));
    return 0;
  }
  if (input.data.request !== undefined) throw new Error("api-applications accepts a session only");
  io.stdout(serializeJson(await listApplicantApplications({
    apiBase, pageOrigin, session: input.data.session,
  })));
  return 0;
}
