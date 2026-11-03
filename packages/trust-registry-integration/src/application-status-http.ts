import { Buffer } from "node:buffer";

import type { MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";

import { createAttestedApplicationStatusSource } from "./application-status-attestation.js";
import { ApplicationVpDependencyUnavailableError } from "./application-vp-verifier.js";

const MAX_STATUS_RESPONSE_BYTES = 64 * 1024;

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
      const contentLength = response.headers.get("content-length");
      if (contentLength !== null && !/^(0|[1-9][0-9]*)$/u.test(contentLength)) {
        void response.body?.cancel().catch(() => {});
        throw new Error("Status attestation Content-Length is malformed");
      }
      if (contentLength !== null && BigInt(contentLength) > BigInt(MAX_STATUS_RESPONSE_BYTES)) {
        void response.body?.cancel().catch(() => {});
        throw new Error("Status attestation response exceeds size limit");
      }
      const reader = response.body?.getReader();
      if (!reader) throw new Error("Status attestation response is empty");
      const chunks: Uint8Array[] = [];
      let length = 0;
      try {
        while (true) {
          let result: ReadableStreamReadResult<Uint8Array>;
          try {
            result = await reader.read();
          } catch {
            throw new ApplicationVpDependencyUnavailableError();
          }
          const { done, value } = result;
          if (done) break;
          length += value.byteLength;
          if (length > MAX_STATUS_RESPONSE_BYTES) {
            void reader.cancel().catch(() => {});
            throw new Error("Status attestation response exceeds size limit");
          }
          chunks.push(value);
        }
      } finally {
        reader.releaseLock();
      }
      return JSON.parse(new TextDecoder("utf-8", { fatal: true })
        .decode(Buffer.concat(chunks))) as unknown;
    },
  });
}
