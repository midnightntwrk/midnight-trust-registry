import { isIP } from "node:net";

import { assertOnlyLedgerRoutes } from "./standalone-egress-route-policy.mjs";

/** @typedef {import("./standalone-egress-route-policy.mjs").LedgerSubnet} LedgerSubnet */
/** @typedef {{code: number, stdout: string}} ProbeResult */
/** @typedef {{subnet: LedgerSubnet, routeTable: string, canaryAddress: string,
 * controlBefore?: ProbeResult, isolated: ProbeResult, controlAfter: ProbeResult,
 * dnsControlBefore?: ProbeResult, dnsIsolated?: ProbeResult, dnsControlAfter: ProbeResult}} ApiEgressProbeInput */

const deniedCodes = new Set(["ENETUNREACH", "EHOSTUNREACH", "ETIMEDOUT"]);
const deniedDnsCodes = new Set(["ETIMEOUT", "ENETUNREACH", "EHOSTUNREACH"]);
const dnsCanaryAddress = "198.51.100.7";

/** @param {ApiEgressProbeInput} input */
export function validateApiEgressProbe(input) {
  const { subnet, routeTable, canaryAddress, controlBefore, isolated, controlAfter,
    dnsControlBefore, dnsIsolated, dnsControlAfter } = input;
  if (isIP(canaryAddress) !== 4) throw new Error("Canary address is not IPv4");
  const address = canaryAddress.split(".").reduce((value, octet) =>
    ((value << 8) | Number(octet)) >>> 0, 0);
  if (((address & subnet.mask) >>> 0) === subnet.address) {
    throw new Error("Canary is inside the API's isolated subnet");
  }
  assertOnlyLedgerRoutes(routeTable, subnet);
  if (controlBefore?.code !== 0 || controlBefore.stdout.trim() !== "connected"
    || controlAfter.code !== 0 || controlAfter.stdout.trim() !== "connected") {
    throw new Error("Bridge canary positive control was not reachable throughout the probe");
  }
  if (isolated.code !== 7 || !deniedCodes.has(isolated.stdout.trim().replace(/^denied:/u, ""))
    || !isolated.stdout.trim().startsWith("denied:")) {
    throw new Error("Running API container did not show an outbound route denial");
  }
  for (const control of [dnsControlBefore, dnsControlAfter]) {
    if (control?.code !== 0 || control.stdout.trim() !== `resolved:${dnsCanaryAddress}`) {
      throw new Error("Bridge DNS positive control did not resolve the local canary");
    }
  }
  if (dnsIsolated?.code !== 7
    || !dnsIsolated.stdout.trim().startsWith("denied:")
    || !deniedDnsCodes.has(dnsIsolated.stdout.trim().slice("denied:".length))) {
    throw new Error("Running API container did not deny the bridge DNS canary route");
  }
}
