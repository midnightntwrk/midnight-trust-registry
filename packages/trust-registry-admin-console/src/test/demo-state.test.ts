import { describe, expect, it } from "vitest";
import { countVotes, parseDemoVotes, voteOutcome } from "../demo-state.js";

describe("guided demo votes", () => {
  it("requires three distinct maintainer personas", () => {
    const votes = parseDemoVotes('{"1":"approve","2":"approve","3":"approve","4":"reject"}');
    expect(countVotes(votes)).toEqual({ approve: 3, reject: 1 });
    expect(voteOutcome(votes)).toBe("approve");
  });

  it("can reject by three distinct personas", () => {
    expect(voteOutcome({ 1: "reject", 2: "reject", 3: "reject" })).toBe("reject");
  });

  it("ignores malformed and unknown local browser state", () => {
    expect(parseDemoVotes("{")).toEqual({});
    expect(parseDemoVotes('{"1":"approve","2":"invalid","99":"approve"}')).toEqual({ 1: "approve" });
    expect(voteOutcome({ 1: "approve", 2: "approve", 3: "reject" })).toBeUndefined();
  });
});
