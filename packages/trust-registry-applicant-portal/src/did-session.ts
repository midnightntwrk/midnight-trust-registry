import {
  signInActorDid,
  signOutActorDid,
  type ActorDidSession,
  type ActorDidSigner,
  type SignInActorDidInput,
} from "@midnightntwrk/trust-registry-client/browser-authentication";

export type ApplicantDidSigner = ActorDidSigner;
export type ApplicantDidSession = ActorDidSession<"applicant-session">;

export function signInApplicantDid(
  input: Omit<SignInActorDidInput<"applicant-session">, "purpose">,
): Promise<ApplicantDidSession> {
  return signInActorDid({ ...input, purpose: "applicant-session" });
}

export function signOutApplicantDid(input: {
  apiBase: string;
  pageOrigin: string;
  session: ApplicantDidSession;
  fetchImpl?: typeof fetch;
}): Promise<void> {
  return signOutActorDid(input);
}
