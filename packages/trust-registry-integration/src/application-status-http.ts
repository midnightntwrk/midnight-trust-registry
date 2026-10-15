import type { MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";

import { createAttestedApplicationStatusSource } from "./application-status-attestation.js";
import { ApplicationVpDependencyUnavailableError } from "./application-vp-verifier.js";

const statusEndpoint = (value: string): URL => {
  const url = new URL(value);
  if (url.username !== "" || url.password !== "" || url.hash !== "" || url.search !== ""
    || (url.protocol !== "https:" && !(url.protocol === "http:"
      && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) {
    throw new Error("Status attestation endpoint must be HTTPS or loopback HTTP without URL credentials");
  }
  return url;
};

/** Transport only: the response remains untrusted until the DID signature and governed binding verify. */
export function createHttpApplicationStatusSource(input: {
  endpointUrl: string;
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  fetchImpl?: typeof fetch;
}) {
  const url = statusEndpoint(input.endpointUrl);
  const fetchImpl = input.fetchImpl ?? fetch;
  return createAttestedApplicationStatusSource({
    resolver: input.resolver,
    fetchAttestation: async (request) => {
      let response: Response;
      try {
        response = await fetchImpl(url, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(request),
          cache: "no-store",
          redirect: "error",
          signal: AbortSignal.timeout(5_000),
        });
      } catch {
        throw new ApplicationVpDependencyUnavailableError();
      }
      if (response.redirected || response.status >= 500 || response.status === 429) {
        throw new ApplicationVpDependencyUnavailableError();
      }
      if (!response.ok) throw new Error(`Status attestation rejected (${response.status})`);
      let body: string;
      try {
        body = await response.text();
      } catch {
        throw new ApplicationVpDependencyUnavailableError();
      }
      return JSON.parse(body) as unknown;
    },
  });
}
