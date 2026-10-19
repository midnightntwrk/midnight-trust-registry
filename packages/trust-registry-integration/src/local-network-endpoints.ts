import { isIP } from "node:net";

const localHost = (hostname: string): boolean => {
  const host = hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (host === "localhost") return true;
  if (isIP(host) === 4) {
    const [a, b] = host.split(".").map(Number);
    return a === 127 || a === 10 || (a === 172 && b! >= 16 && b! <= 31)
      || (a === 192 && b === 168);
  }
  if (isIP(host) === 6) {
    if (host === "::1") return true;
    const first = Number.parseInt(host.split(":")[0]!, 16);
    return (first & 0xfe00) === 0xfc00;
  }
  return /^[a-z][a-z0-9-]*$/u.test(host);
};

/** An exact allowlist is required in addition to host-level egress controls. */
export function localNetworkEndpoint(
  value: string,
  allowedHosts: readonly string[],
  protocols: readonly string[],
): string {
  if (allowedHosts.length === 0 || allowedHosts.some((host) => !localHost(host))) {
    throw new Error("Local service host allowlist must contain only private hosts or single-label aliases");
  }
  const endpoint = new URL(value);
  if (!protocols.includes(endpoint.protocol)
    || !localHost(endpoint.hostname)
    || !allowedHosts.some((host) => host.toLowerCase() === endpoint.hostname.toLowerCase())) {
    throw new Error("Local service endpoint is not on the approved private host allowlist");
  }
  if (endpoint.username !== "" || endpoint.password !== "" || endpoint.hash !== "" || endpoint.search !== "") {
    throw new Error("Local service endpoint must not contain credentials, query, or fragment");
  }
  return endpoint.toString();
}
