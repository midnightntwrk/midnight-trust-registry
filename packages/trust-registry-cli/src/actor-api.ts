import { parseArgs } from "node:util";

import { listApplicantApplications, registerApplicantApplication } from "@midnight-ntwrk/trust-registry-client/browser-authentication";
import { SignedPendingApplicationSchema } from "@midnight-ntwrk/trust-registry-domain/browser";
import { z } from "zod";

import { serializeJson } from "./model.js";

const MAX_INPUT_BYTES = 128 * 1024;

const ApplicantSessionSchema = z.strictObject({
  actorDid: z.string().startsWith("did:midnight:"),
  actorKeyId: z.string().min(1),
  purpose: z.literal("applicant-session"),
  origin: z.string().url(),
  registryId: z.string().min(1),
  genesisHash: z.string().regex(/^0x[0-9a-f]{64}$/u),
  contractAddress: z.string().regex(/^0x[0-9a-f]{64}$/u),
  accessToken: z.string().regex(/^trsa_[A-Za-z0-9_-]{43}$/u),
  expiresAt: z.string().datetime({ offset: true }),
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

/** A caller supplies an ephemeral session and signed intent; the CLI never handles a private key. */
export async function runActorApiCommand(
  command: "api-register" | "api-applications",
  argv: readonly string[],
  io: ActorCliIo,
): Promise<number> {
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
  if (input.data.request !== undefined) throw new Error("api-applications accepts a session only");
  io.stdout(serializeJson(await listApplicantApplications({
    apiBase, pageOrigin, session: input.data.session,
  })));
  return 0;
}
