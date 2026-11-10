export const DEMO_MAINTAINERS = [1, 2, 3, 4, 5] as const;
export const DEMO_QUORUM = 3;

export type DemoVote = "approve" | "reject";
export type DemoVotes = Partial<Record<(typeof DEMO_MAINTAINERS)[number], DemoVote>>;

export const countVotes = (votes: DemoVotes): { approve: number; reject: number } => ({
  approve: DEMO_MAINTAINERS.filter((maintainer) => votes[maintainer] === "approve").length,
  reject: DEMO_MAINTAINERS.filter((maintainer) => votes[maintainer] === "reject").length,
});

export const voteOutcome = (votes: DemoVotes): DemoVote | undefined => {
  const counts = countVotes(votes);
  if (counts.approve >= DEMO_QUORUM) return "approve";
  if (counts.reject >= DEMO_QUORUM) return "reject";
  return undefined;
};

export const parseDemoVotes = (value: string | null): DemoVotes => {
  if (value === null) return {};
  try {
    const candidate: unknown = JSON.parse(value);
    if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) return {};
    const votes: DemoVotes = {};
    for (const maintainer of DEMO_MAINTAINERS) {
      const vote = (candidate as Record<string, unknown>)[maintainer];
      if (vote === "approve" || vote === "reject") votes[maintainer] = vote;
    }
    return votes;
  } catch {
    return {};
  }
};
