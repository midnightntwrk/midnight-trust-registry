/** @typedef {{address: number, mask: number, prefix: number, text: string}} LedgerSubnet */
/** @typedef {{Id?: string, Internal?: boolean, EnableIPv6?: boolean, IPAM?: {Config?: Array<{Subnet?: string}>}}} LedgerNetwork */

/** @param {string} hex */
function routeAddress(hex) {
  const bytes = hex.match(/../gu);
  if (!bytes || bytes.length !== 4) throw new Error("Route address is malformed");
  return ((Number.parseInt(bytes[3], 16) << 24) | (Number.parseInt(bytes[2], 16) << 16)
    | (Number.parseInt(bytes[1], 16) << 8) | Number.parseInt(bytes[0], 16)) >>> 0;
}

/** @param {string} hexMask */
function routePrefixLength(hexMask) {
  if (!/^[0-9a-fA-F]{8}$/u.test(hexMask)) return null;
  const mask = routeAddress(hexMask);
  const hostMask = (~mask) >>> 0;
  if ((hostMask & ((hostMask + 1) >>> 0)) !== 0) return null;
  return Math.clz32(hostMask);
}

/** @param {string} value */
function ipv4Address(value) {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part)
    || Number(part) > 255)) return null;
  return parts.reduce((address, part) => ((address << 8) | Number(part)) >>> 0, 0);
}

/** @param {LedgerNetwork | undefined} network @param {string} expectedId @returns {LedgerSubnet} */
export function ledgerSubnet(network, expectedId) {
  if (network?.Id !== expectedId || network?.Internal !== true
    || network?.EnableIPv6 !== false || network?.IPAM?.Config?.length !== 1) {
    throw new Error("Observed ledger network IPAM differs from the isolated topology");
  }
  const subnet = network.IPAM.Config[0]?.Subnet;
  const match = typeof subnet === "string" ? /^(\d+(?:\.\d+){3})\/(\d{1,2})$/u.exec(subnet) : null;
  const address = match ? ipv4Address(match[1]) : null;
  const prefix = match ? Number(match[2]) : null;
  if (typeof subnet !== "string" || address === null || prefix === null
    || !Number.isInteger(prefix) || prefix < 1 || prefix > 32) {
    throw new Error("Ledger bridge has no valid IPv4 subnet");
  }
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  if (((address & mask) >>> 0) !== address) throw new Error("Ledger bridge subnet is not canonical");
  return { address, mask, prefix, text: subnet };
}

/** @param {string} routeTable @param {LedgerSubnet} subnet */
export function assertOnlyLedgerRoutes(routeTable, subnet) {
  if (!hasValidRouteTable(routeTable)) throw new Error("Ledger route table is malformed");
  const lines = routeTable.trim().split("\n").slice(1);
  for (const line of lines) {
    const columns = line.trim().split(/\s+/u);
    const prefix = routePrefixLength(columns[7]);
    const destination = routeAddress(columns[1]);
    if (prefix === null || prefix < subnet.prefix
      || ((destination & subnet.mask) >>> 0) !== subnet.address) {
      throw new Error("Ledger bridge route escapes the observed subnet");
    }
  }
}

/** @param {string} routeTable */
export function hasBroadOutboundRoute(routeTable) {
  return routeTable.split("\n").slice(1).some((line) => {
    const columns = line.trim().split(/\s+/u);
    if (columns.length < 8) return false;
    const prefix = routePrefixLength(columns[7]);
    return prefix !== null && prefix <= 8;
  });
}

/** @param {string} routeTable */
export function hasValidRouteTable(routeTable) {
  const lines = routeTable.trim().split("\n");
  if (!/^Iface\s+Destination\s+Gateway\s+Flags\s+/u.test(lines[0] ?? "")
    || lines.length < 2) return false;
  return lines.slice(1).every((line) => {
    const columns = line.trim().split(/\s+/u);
    return columns.length >= 8
      && /^[0-9a-fA-F]{8}$/u.test(columns[1])
      && routePrefixLength(columns[7]) !== null;
  });
}

/** @param {string} output */
export function parseCanaryAddress(output) {
  const address = output.match(/^((?:\d{1,3}\.){3}\d{1,3})\s/mu)?.[1];
  if (!address || address.split(".").some((part) => Number(part) > 255)) {
    throw new Error("Canary did not resolve to an IPv4 address");
  }
  return address;
}

/** @param {{controlRoute: string, isolatedRoute: string, controlCode: number,
 * isolatedCode: number, isolatedDnsCode: number, isolatedDnsOutput: string}} input */
export function validateEgressProbe({ controlRoute, isolatedRoute, controlCode, isolatedCode,
  isolatedDnsCode, isolatedDnsOutput }) {
  if (!hasValidRouteTable(controlRoute) || !hasValidRouteTable(isolatedRoute)) {
    throw new Error("Probe route table is empty or malformed");
  }
  if (!hasBroadOutboundRoute(controlRoute)) {
    throw new Error("Positive-control container has no broad outbound route");
  }
  if (hasBroadOutboundRoute(isolatedRoute)) {
    throw new Error("Isolated ledger network unexpectedly has a broad outbound route");
  }
  if (controlCode !== 0) {
    throw new Error("Positive-control HTTPS request did not succeed");
  }
  if (isolatedCode !== 7) {
    throw new Error("Isolated HTTPS request did not fail with a connection error");
  }
  if (isolatedDnsCode !== 2 || isolatedDnsOutput.trim() !== "") {
    throw new Error("Isolated canary DNS resolution was not denied");
  }
}
