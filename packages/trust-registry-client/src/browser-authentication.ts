import {
  ActorAuthenticationChallengeSchema,
  ActorAuthenticationSignatureSchema,
  actorAuthenticationDigestBytes,
  PendingApplicationListResponseSchema,
  PendingApplicationRecordSchema,
  SignedPendingApplicationSchema,
  type ActorAuthenticationChallenge,
  type ActorAuthenticationPurpose,
  type ActorAuthenticationSignature,
  type PendingApplicationSummary,
  type PendingApplicationRecord,
  type SignedPendingApplication,
} from "@midnight-ntwrk/trust-registry-domain/browser";

const TOKEN_PATTERN = /^trsa_[A-Za-z0-9_-]{43}$/u;
const MAX_SESSION_AGE_MS = 15 * 60 * 1000;

export interface ActorDidSigner {
  getIdentity(): Promise<{ actorDid: string; actorKeyId: string }>;
  signDigest(input: { challenge: ActorAuthenticationChallenge; digest: Uint8Array }): Promise<ActorAuthenticationSignature>;
}

export function isActorDidSigner(value: unknown): value is ActorDidSigner {
  if (value === null || typeof value !== "object") return false;
  try {
    return typeof (value as Record<string, unknown>).getIdentity === "function"
      && typeof (value as Record<string, unknown>).signDigest === "function";
  } catch {
    return false;
  }
}

export type ActorDidSession<P extends ActorAuthenticationPurpose = ActorAuthenticationPurpose> = {
  actorDid: string;
  actorKeyId: string;
  purpose: P;
  origin: string;
  registryId: string;
  genesisHash: string;
  contractAddress: string;
  accessToken: string;
  expiresAt: string;
};

export type SignInActorDidInput<P extends ActorAuthenticationPurpose> = {
  apiBase: string;
  pageOrigin: string;
  registryId: string;
  purpose: P;
  deploymentIdentity?: { expectedGenesisHash: string; contractAddress: string };
  signer: ActorDidSigner;
  fetchImpl?: typeof fetch;
  clock?: () => number;
};

export function isSameOriginPrivateApi(apiBase: string, pageOrigin: string): boolean {
  try {
    const url = new URL(apiBase);
    return url.origin === pageOrigin && url.username === "" && url.password === ""
      && (url.protocol === "https:" || (url.protocol === "http:"
        && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)));
  } catch {
    return false;
  }
}

function sameOriginApi(apiBase: string, pageOrigin: string): string {
  if (!isSameOriginPrivateApi(apiBase, pageOrigin)) {
    throw new Error("DID sign-in requires the same trusted API origin as this page.");
  }
  return new URL(apiBase).href.replace(/\/$/u, "");
}

async function responsePayload(response: Response, action: string): Promise<unknown> {
  if (!response.ok) throw new Error(`${action} failed (HTTP ${response.status.toString()}).`);
  try {
    return await response.json() as unknown;
  } catch {
    throw new Error(`${action} returned an invalid response.`);
  }
}

/** The external signer owns the private key; this client holds only an ephemeral identity session. */
export async function signInActorDid<P extends ActorAuthenticationPurpose>(
  input: SignInActorDidInput<P>,
): Promise<ActorDidSession<P>> {
  const base = sameOriginApi(input.apiBase, input.pageOrigin);
  const fetchImpl = input.fetchImpl ?? fetch;
  const clock = input.clock ?? Date.now;
  const { actorDid, actorKeyId } = await input.signer.getIdentity();
  const challengeResponse = await fetchImpl(`${base}/v1/actor-authentication/challenges`, {
    method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ actorDid, actorKeyId, purpose: input.purpose }),
  });
  const challengeValue = await responsePayload(challengeResponse, "DID challenge");
  const parsed = ActorAuthenticationChallengeSchema.safeParse(challengeValue);
  if (!parsed.success || parsed.data.actorDid !== actorDid || parsed.data.actorKeyId !== actorKeyId
    || parsed.data.registryId !== input.registryId || parsed.data.origin !== input.pageOrigin
    || parsed.data.purpose !== input.purpose
    || (actorDid.startsWith("did:midnight:offchain:")
      ? parsed.data.version !== "tr-actor-authentication-offchain-v1"
      : parsed.data.version !== "tr-actor-authentication-v1")
    || (input.deploymentIdentity !== undefined && (parsed.data.genesisHash !== input.deploymentIdentity.expectedGenesisHash
      || parsed.data.contractAddress !== input.deploymentIdentity.contractAddress))) {
    throw new Error("DID challenge does not match this actor and registry.");
  }
  const challenge = parsed.data;
  if (Date.parse(challenge.expiresAt) <= clock()) throw new Error("DID challenge has expired.");
  const signed = ActorAuthenticationSignatureSchema.safeParse(await input.signer.signDigest({
    challenge, digest: actorAuthenticationDigestBytes(challenge),
  }));
  if (!signed.success || signed.data.keyId !== actorKeyId
    || signed.data.algorithm !== (challenge.version === "tr-actor-authentication-v1"
      ? "jubjub-schnorr" : "ed25519")) {
    throw new Error("DID signer returned a mismatched signature.");
  }
  const sessionResponse = await fetchImpl(`${base}/v1/actor-authentication/sessions`, {
    method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge, signature: signed.data }),
  });
  const session = await responsePayload(sessionResponse, "DID sign-in");
  if (session === null || typeof session !== "object" || Array.isArray(session)) {
    throw new Error("DID sign-in returned an invalid session.");
  }
  const value = session as Record<string, unknown>;
  const expiresAt = typeof value.expiresAt === "string" ? Date.parse(value.expiresAt) : NaN;
  if (value.actorDid !== actorDid || value.actorKeyId !== actorKeyId || value.purpose !== input.purpose
    || typeof value.accessToken !== "string" || !TOKEN_PATTERN.test(value.accessToken)
    || !Number.isFinite(expiresAt) || expiresAt <= clock() || expiresAt - clock() > MAX_SESSION_AGE_MS) {
    throw new Error("DID sign-in returned a mismatched session.");
  }
  return { actorDid, actorKeyId, purpose: input.purpose, origin: input.pageOrigin, registryId: input.registryId,
    genesisHash: challenge.genesisHash, contractAddress: challenge.contractAddress,
    accessToken: value.accessToken, expiresAt: value.expiresAt as string };
}

export async function signOutActorDid(input: {
  apiBase: string;
  pageOrigin: string;
  session: ActorDidSession;
  fetchImpl?: typeof fetch;
}): Promise<void> {
  const base = sameOriginApi(input.apiBase, input.pageOrigin);
  if (input.session.origin !== input.pageOrigin) throw new Error("DID session origin does not match this page.");
  const response = await (input.fetchImpl ?? fetch)(`${base}/v1/actor-authentication/session`, {
    method: "DELETE", credentials: "omit", cache: "no-store", redirect: "error",
    headers: { authorization: `Bearer ${input.session.accessToken}` },
  });
  if (!response.ok) throw new Error(`DID sign-out failed (HTTP ${response.status.toString()}).`);
}

export type ApplicantApplicationList =
  | { status: "available"; entries: readonly PendingApplicationSummary[] }
  | { status: "unavailable" };

function currentApplicantSession(session: ActorDidSession<"applicant-session">, clock: () => number): void {
  const expiresAt = Date.parse(session.expiresAt);
  if (session.purpose !== "applicant-session" || !TOKEN_PATTERN.test(session.accessToken)
    || !Number.isFinite(expiresAt) || expiresAt <= clock()) {
    throw new Error("A current applicant DID session is required.");
  }
}

/** Register a signed applicant intent without placing signer key material in this client. */
export async function registerApplicantApplication(input: {
  apiBase: string;
  pageOrigin: string;
  session: ActorDidSession<"applicant-session">;
  request: SignedPendingApplication;
  fetchImpl?: typeof fetch;
  clock?: () => number;
}): Promise<PendingApplicationRecord> {
  const base = sameOriginApi(input.apiBase, input.pageOrigin);
  if (input.session.origin !== input.pageOrigin) throw new Error("Applicant DID session origin does not match this page.");
  const clock = input.clock ?? Date.now;
  currentApplicantSession(input.session, clock);
  const request = SignedPendingApplicationSchema.parse(input.request);
  if (request.intent.actorDid !== input.session.actorDid
    || request.intent.actorKeyId !== input.session.actorKeyId
    || request.intent.registryId !== input.session.registryId
    || Date.parse(request.intent.expiresAt) <= clock()) {
    throw new Error("Signed application does not match the current applicant DID session.");
  }
  let response: Response;
  try {
    response = await (input.fetchImpl ?? fetch)(`${base}/v1/pending-applications`, {
      method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
      headers: { "content-type": "application/json", authorization: `Bearer ${input.session.accessToken}` },
      body: JSON.stringify(request),
    });
  } catch {
    throw new Error("Pending application outcome is unknown after transport failure. Do not resubmit the signed request; reconcile it by exact request identity.");
  }
  const parsed = PendingApplicationRecordSchema.safeParse(await responsePayload(response, "Pending application registration"));
  if (!parsed.success || parsed.data.status !== "pending"
    || parsed.data.binding.applicationId !== request.applicationId
    || parsed.data.authorizationId !== request.authorizationId
    || parsed.data.binding.registryId !== input.session.registryId
    || parsed.data.binding.subjectDid !== input.session.actorDid
    || parsed.data.binding.role !== request.scope.role
    || parsed.data.binding.scopeCommitment !== request.intent.scopeCommitment
    || parsed.data.binding.governedResource.type !== request.governedResource.type
    || parsed.data.binding.governedResource.id !== request.governedResource.id) {
    throw new Error("Pending application registration returned a mismatched record. Do not resubmit the signed request; reconcile it by exact request identity.");
  }
  return parsed.data;
}

export async function listApplicantApplications(input: {
  apiBase: string;
  pageOrigin: string;
  session: ActorDidSession<"applicant-session">;
  fetchImpl?: typeof fetch;
  clock?: () => number;
}): Promise<ApplicantApplicationList> {
  const base = sameOriginApi(input.apiBase, input.pageOrigin);
  if (input.session.origin !== input.pageOrigin) throw new Error("Applicant DID session origin does not match this page.");
  currentApplicantSession(input.session, input.clock ?? Date.now);
  const response = await (input.fetchImpl ?? fetch)(`${base}/v1/pending-applications`, {
    method: "GET", credentials: "omit", cache: "no-store", redirect: "error",
    headers: { authorization: `Bearer ${input.session.accessToken}` },
  });
  if (response.status === 503) {
    const problem: unknown = await response.json().catch(() => null);
    if (problem !== null && typeof problem === "object" && "type" in problem
      && typeof problem.type === "string"
      && problem.type.endsWith("/pending-application-list-unavailable")) {
      return { status: "unavailable" };
    }
  }
  const payload = await responsePayload(response, "Pending application list");
  const parsed = PendingApplicationListResponseSchema.safeParse(payload);
  if (!parsed.success) throw new Error("Pending application list returned an invalid response.");
  return { status: "available", entries: parsed.data.entries };
}
