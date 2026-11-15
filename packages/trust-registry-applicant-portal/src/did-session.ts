import {
  ActorAuthenticationChallengeSchema,
  MutationIntentSignatureSchema,
  actorAuthenticationDigestBytes,
  type ActorAuthenticationChallenge,
  type MutationIntentSignature,
} from "@midnight-ntwrk/trust-registry-domain/browser";

const TOKEN_PATTERN = /^trsa_[A-Za-z0-9_-]{43}$/u;
const MAX_SESSION_AGE_MS = 15 * 60 * 1000;

export interface ApplicantDidSigner {
  getIdentity(): Promise<{ actorDid: string; actorKeyId: string }>;
  signDigest(input: { challenge: ActorAuthenticationChallenge; digest: Uint8Array }): Promise<MutationIntentSignature>;
}

export type ApplicantDidSession = {
  actorDid: string;
  actorKeyId: string;
  registryId: string;
  genesisHash: string;
  contractAddress: string;
  accessToken: string;
  expiresAt: string;
};

function sameOriginApi(apiBase: string, pageOrigin: string): string {
  const url = new URL(apiBase);
  if (url.origin !== pageOrigin || url.username !== "" || url.password !== ""
    || (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) {
    throw new Error("DID sign-in requires the same trusted API origin as this page.");
  }
  return url.href.replace(/\/$/u, "");
}

async function responsePayload(response: Response, action: string): Promise<unknown> {
  if (!response.ok) throw new Error(`${action} failed (HTTP ${response.status.toString()}).`);
  try {
    return await response.json() as unknown;
  } catch {
    throw new Error(`${action} returned an invalid response.`);
  }
}

/** The external signer owns the private key; this client only holds an ephemeral identity session. */
export async function signInApplicantDid(input: {
  apiBase: string;
  pageOrigin: string;
  registryId: string;
  deploymentIdentity?: { expectedGenesisHash: string; contractAddress: string };
  signer: ApplicantDidSigner;
  fetchImpl?: typeof fetch;
  clock?: () => number;
}): Promise<ApplicantDidSession> {
  const base = sameOriginApi(input.apiBase, input.pageOrigin);
  const fetchImpl = input.fetchImpl ?? fetch;
  const clock = input.clock ?? Date.now;
  const { actorDid, actorKeyId } = await input.signer.getIdentity();
  const challengeResponse = await fetchImpl(`${base}/v1/actor-authentication/challenges`, {
    method: "POST", credentials: "omit", cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ actorDid, actorKeyId, purpose: "applicant-session" }),
  });
  const challengeValue = await responsePayload(challengeResponse, "DID challenge");
  const parsed = ActorAuthenticationChallengeSchema.safeParse(challengeValue);
  if (!parsed.success || parsed.data.actorDid !== actorDid || parsed.data.actorKeyId !== actorKeyId
    || parsed.data.registryId !== input.registryId || parsed.data.origin !== input.pageOrigin
    || parsed.data.purpose !== "applicant-session"
    || (input.deploymentIdentity !== undefined && (parsed.data.genesisHash !== input.deploymentIdentity.expectedGenesisHash
      || parsed.data.contractAddress !== input.deploymentIdentity.contractAddress))) {
    throw new Error("DID challenge does not match this actor and registry.");
  }
  const challenge = parsed.data;
  if (Date.parse(challenge.expiresAt) <= clock()) throw new Error("DID challenge has expired.");
  const signed = MutationIntentSignatureSchema.safeParse(await input.signer.signDigest({
    challenge, digest: actorAuthenticationDigestBytes(challenge),
  }));
  if (!signed.success || signed.data.keyId !== actorKeyId) {
    throw new Error("DID signer returned a mismatched signature.");
  }
  const sessionResponse = await fetchImpl(`${base}/v1/actor-authentication/sessions`, {
    method: "POST", credentials: "omit", cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge, signature: signed.data }),
  });
  const session = await responsePayload(sessionResponse, "DID sign-in");
  if (session === null || typeof session !== "object" || Array.isArray(session)) {
    throw new Error("DID sign-in returned an invalid session.");
  }
  const value = session as Record<string, unknown>;
  const expiresAt = typeof value.expiresAt === "string" ? Date.parse(value.expiresAt) : NaN;
  if (value.actorDid !== actorDid || value.actorKeyId !== actorKeyId || value.purpose !== "applicant-session"
    || typeof value.accessToken !== "string" || !TOKEN_PATTERN.test(value.accessToken)
    || !Number.isFinite(expiresAt) || expiresAt <= clock() || expiresAt - clock() > MAX_SESSION_AGE_MS) {
    throw new Error("DID sign-in returned a mismatched session.");
  }
  return { actorDid, actorKeyId, registryId: input.registryId,
    genesisHash: challenge.genesisHash, contractAddress: challenge.contractAddress,
    accessToken: value.accessToken, expiresAt: value.expiresAt as string };
}

export async function signOutApplicantDid(input: {
  apiBase: string;
  pageOrigin: string;
  session: ApplicantDidSession;
  fetchImpl?: typeof fetch;
}): Promise<void> {
  const base = sameOriginApi(input.apiBase, input.pageOrigin);
  const response = await (input.fetchImpl ?? fetch)(`${base}/v1/actor-authentication/session`, {
    method: "DELETE", credentials: "omit", cache: "no-store",
    headers: { authorization: `Bearer ${input.session.accessToken}` },
  });
  if (!response.ok) throw new Error(`DID sign-out failed (HTTP ${response.status.toString()}).`);
}
