import { createHash, randomBytes } from "node:crypto";

import type { ActorAuthenticationPurpose } from "@midnight-ntwrk/trust-registry-domain";

const SESSION_LIFETIME_MS = 15 * 60 * 1000;
const MAX_SESSIONS = 1024;
const MAX_SESSIONS_PER_ACTOR = 4;
const TOKEN_PATTERN = /^trsa_[A-Za-z0-9_-]{43}$/u;

export type ActorSessionIdentity = {
  actorDid: string;
  actorKeyId: string;
  purpose: ActorAuthenticationPurpose;
};

type StoredSession = ActorSessionIdentity & { expiresAtMs: number };

function tokenDigest(token: string): string {
  return createHash("sha256").update("tr:actor:session:v1:").update(token).digest("hex");
}

/** Process-local, bearer-only sessions. Restart revokes all tokens; no registry authority is inferred. */
export function createActorSessionService(clock: () => number) {
  const sessions = new Map<string, StoredSession>();
  const now = () => {
    const value = clock();
    if (!Number.isSafeInteger(value)) throw new Error("Actor session clock unavailable");
    return value;
  };
  const discardExpired = (at: number) => {
    for (const [digest, session] of sessions) {
      if (session.expiresAtMs <= at) sessions.delete(digest);
    }
  };
  const parseBearer = (header: string | undefined) => {
    if (header === undefined || !/^Bearer /iu.test(header)) return null;
    const token = header.slice("Bearer ".length);
    return TOKEN_PATTERN.test(token) ? token : null;
  };

  return {
    issue(identity: ActorSessionIdentity) {
      const at = now();
      discardExpired(at);
      const actorSessions = [...sessions].filter(([, session]) => session.actorDid === identity.actorDid);
      if (actorSessions.length >= MAX_SESSIONS_PER_ACTOR) sessions.delete(actorSessions[0]![0]);
      if (sessions.size >= MAX_SESSIONS) throw new Error("Actor session capacity unavailable");
      const accessToken = `trsa_${randomBytes(32).toString("base64url")}`;
      const expiresAtMs = at + SESSION_LIFETIME_MS;
      sessions.set(tokenDigest(accessToken), { ...identity, expiresAtMs });
      return { accessToken, expiresAt: new Date(expiresAtMs).toISOString(), ...identity };
    },
    authenticate(header: string | undefined, purpose?: ActorAuthenticationPurpose): ActorSessionIdentity | null {
      const token = parseBearer(header);
      if (token === null) return null;
      const digest = tokenDigest(token);
      const session = sessions.get(digest);
      if (session === undefined) return null;
      if (session.expiresAtMs <= now()) {
        sessions.delete(digest);
        return null;
      }
      if (purpose !== undefined && session.purpose !== purpose) return null;
      return { actorDid: session.actorDid, actorKeyId: session.actorKeyId, purpose: session.purpose };
    },
    revoke(header: string | undefined): boolean {
      const token = parseBearer(header);
      if (token === null) return false;
      const digest = tokenDigest(token);
      const session = sessions.get(digest);
      if (session === undefined) return false;
      const live = session.expiresAtMs > now();
      sessions.delete(digest);
      return live;
    },
  };
}

export type ActorSessionService = ReturnType<typeof createActorSessionService>;
