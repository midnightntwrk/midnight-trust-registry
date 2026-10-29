import { describe, expect, it } from "vitest";

import { localNetworkEndpoint } from "../local-network-endpoints.js";

describe("isolated local service endpoints", () => {
  it.each([
    ["http://127.0.0.1:9944", ["127.0.0.1"], ["http:"]],
    ["http://node:9944", ["node"], ["http:"]],
    ["ws://indexer:8080/graphql/ws", ["indexer"], ["ws:"]],
    ["https://10.10.0.2/rpc", ["10.10.0.2"], ["https:"]],
    ["http://172.20.0.2:9944", ["172.20.0.2"], ["http:"]],
    ["http://192.168.1.5:9944", ["192.168.1.5"], ["http:"]],
    ["http://[::1]:9944", ["[::1]"], ["http:"]],
    ["http://[fd00::1]:9944", ["[fd00::1]"], ["http:"]],
  ])("accepts approved local endpoint %s", (url, allowedHosts, protocols) => {
    const expected = new URL(url);
    if (["node", "indexer"].includes(expected.hostname)) expected.hostname = `${expected.hostname}.`;
    expect(localNetworkEndpoint(url, allowedHosts, protocols)).toBe(expected.toString());
  });

  it("roots an approved short service name before handing it to the network client", () => {
    expect(localNetworkEndpoint("http://node:9944/rpc", ["node"], ["http:"]))
      .toBe("http://node.:9944/rpc");
    expect(localNetworkEndpoint("ws://indexer:8080/graphql/ws", ["indexer"], ["ws:"]))
      .toBe("ws://indexer.:8080/graphql/ws");
  });

  it.each([
    ["http://public.example:9944", ["public.example"], ["http:"]],
    ["http://8.8.8.8:9944", ["8.8.8.8"], ["http:"]],
    ["http://node:9944", ["other-node"], ["http:"]],
    ["http://node:9944", [], ["http:"]],
    ["ftp://node/resource", ["node"], ["http:"]],
    ["http://user:secret@node:9944", ["node"], ["http:"]],
    ["http://node:9944?token=secret", ["node"], ["http:"]],
    ["http://node:9944/#fragment", ["node"], ["http:"]],
    ["http://172.15.0.1:9944", ["172.15.0.1"], ["http:"]],
    ["http://172.32.0.1:9944", ["172.32.0.1"], ["http:"]],
    ["http://169.254.169.254:80", ["169.254.169.254"], ["http:"]],
    ["http://0.0.0.0:9944", ["0.0.0.0"], ["http:"]],
    ["http://[fe80::1]:9944", ["[fe80::1]"], ["http:"]],
    ["http://[::ffff:8.8.8.8]:9944", ["[::ffff:8.8.8.8]"], ["http:"]],
    ["http://2130706433:9944", ["2130706433"], ["http:"]],
    ["http://0x7f.1:9944", ["0x7f.1"], ["http:"]],
    ["http://node.:9944", ["node."], ["http:"]],
    ["http://10.0.0.1.nip.io:9944", ["10.0.0.1.nip.io"], ["http:"]],
    ["http://node:9944", ["node", "evil.example"], ["http:"]],
  ])("rejects unsafe local endpoint %s", (url, allowedHosts, protocols) => {
    expect(() => localNetworkEndpoint(url, allowedHosts, protocols)).toThrow();
  });
});
