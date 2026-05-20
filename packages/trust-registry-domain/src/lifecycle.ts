import { z } from "zod";

export const LifecycleStatusSchema = z.enum([
  "proposed",
  "authorized",
  "active",
  "suspended",
  "revoked",
  "superseded",
  "archived",
]);

export type LifecycleStatus = z.infer<typeof LifecycleStatusSchema>;

const lifecycleTransitionMap: Record<LifecycleStatus, LifecycleStatus[]> = {
  proposed: ["authorized", "archived"],
  authorized: ["active", "revoked", "archived"],
  active: ["suspended", "revoked", "superseded", "archived"],
  suspended: ["active", "revoked", "superseded", "archived"],
  revoked: ["archived"],
  superseded: ["archived"],
  archived: [],
};

export function canTransitionLifecycleStatus(
  from: LifecycleStatus,
  to: LifecycleStatus,
): boolean {
  return lifecycleTransitionMap[from].includes(to);
}

export function assertLifecycleTransition(
  from: LifecycleStatus,
  to: LifecycleStatus,
): void {
  if (!canTransitionLifecycleStatus(from, to)) {
    throw new Error(`Invalid lifecycle transition: ${from} -> ${to}`);
  }
}

export function assertAscendingTimestamps(
  entries: Array<readonly [field: string, value: string | undefined]>,
): void {
  let lastTimestamp = -Infinity;
  let lastField = "start";

  for (const [field, value] of entries) {
    if (value === undefined) {
      continue;
    }

    const timestamp = Date.parse(value);
    if (Number.isNaN(timestamp)) {
      throw new Error(`Invalid timestamp in ${field}`);
    }
    if (timestamp < lastTimestamp) {
      throw new Error(`${field} must not be earlier than ${lastField}`);
    }

    lastTimestamp = timestamp;
    lastField = field;
  }
}

