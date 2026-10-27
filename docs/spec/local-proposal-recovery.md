# Local proposal reservation recovery

Status: **proposed safety contract for issue #220**, not an implemented
recovery procedure or release approval. The first 0.1.0 RC targets a
self-hosted local ledger. This document does not qualify a public network.

## Why an unknown outcome stays blocked

The API writes a deployment-bound `reserved` attempt to its private proposal
journal before calling the submission provider. A lost response can mean that
the action was never broadcast, is still pending, was finalized, or was
finalized but is temporarily invisible to a lagging reader. The provider's
in-memory `inFlightDeployments` and `uncertainDeployments` guards only protect
one process; they do not survive restart. Governed API submission must reopen
the same deployment-bound journal and refuse a second broadcast while the
attempt is `reserved` or otherwise unresolved. A failed durable reservation
must stop before provider submission. A null current-record lookup, a
timeout, or a provider error cannot distinguish these outcomes.

The mocked-node restart test recreates the pinned provider module after a
lost response and confirms that the reopened journal prevents a second
broadcast. Separate HTTP tests restart the API listener, and journal tests
require finalized reconciliation before another action is admitted. These
mechanics tests do not prove live local-ledger finality or recovery.

The current `inspect-local-proposal-recovery` and signed-decision verifier
are **read-only review aids**. A `sequence-invalidated-record-absent` report
shows that a later node-observed governance counter would make the originally
signed action sequence stale *if that observation is authentic*. It neither
proves that the original action did not execute at its sequence nor permits
the journal to be cleared. The packaged local API has no approved recovery
mutator.

## Evidence required before any future terminal decision

For one exact journal attempt, an independent verifier must establish all of
the following, or the reservation remains blocked:

1. The source revision, signed API plan, approved genesis, network, registry,
   contract, journal binding, authorization ID, evidence commitment, action
   sequence, kind, and payload hash identify the *same* deployment and
   attempt. The original journal and all segments must be retained and
   verified under their existing lock. A backup or new journal path cannot
   replace the original history.
2. An independently authenticated finalized checkpoint supplies the
   governance counter and a complete, verifiable account of the governed
   actions from the reserved sequence through that checkpoint. A local
   indexer's null current-record response, node-reported block hash, or
   self-attested API snapshot is insufficient. The reviewer must be able to
   detect omitted or reordered actions, not merely inspect one current row.
3. The finalized counter is **greater** than the reserved action sequence,
   and the complete action account proves that the reserved action did not
   execute at that sequence. Counter advancement alone is not enough: the
   original action could have executed before another action advanced it.
   If a matching finalized action exists, reconcile to `observed`. If a
   conflicting action or incomplete history exists, stop for investigation.
4. The Compact verifier at the approved contract rejects the original signed
   action after the counter advance. The proof must account for the actual
   action-scoped policy and signer bundle, not assume that an authorization
   ID is itself a replay nonce. An unexpired or still-executable signature
   cannot be declared abandoned.
5. A reviewer independent of the API-plan signer examines the raw evidence
   and detached-signs a canonical decision naming the attempt digest,
   checkpoint, evidence digest/reference, outcome, identity, and decision
   time. A signature on a draft without authenticated finality remains an
   audit record only. Private keys and unredacted evidence stay outside PRs.

No existing API reader or current-state projection proves item 2. If the
ledger cannot provide an independently authenticated *complete* action
account, the safe outcome is a permanently blocked reservation until a
separately reviewed protocol-level invalidation or recovery mechanism exists.
Do not infer non-inclusion by searching a bounded time window.

## Required journal transition, not yet implemented

After independent review of the proof format and exact-head code, a future
operator-only transition may atomically turn `reserved` into a terminal
`abandoned` tombstone. It must retain the original authorization ID,
evidence commitment, reservation context, attempt digest, approved decision
digest, evidence reference, reviewer identity, and decision time. It must
never make the same role/authorization ID replayable. The transition must
hold the existing single-host/multi-process lock, validate the deployment
binding and current attempt under that lock, durably write and fsync before
unblocking a different proposal, and fail closed on a crash or changed
checkpoint. Archive rotation, capacity accounting, backup, and restore must
preserve and revalidate the tombstone. No HTTP request may supply its own
proof verdict or select a new journal to bypass this rule.

The transition is deliberately absent today. A signed review decision does
**not** authorize manual JSON edits, journal deletion, a reset, or a retry.

## Acceptance tests for the future implementation

| Case | Required result |
| --- | --- |
| Lost response after broadcast, eventual matching finality | Reconcile to `observed`; never abandon or replay. |
| Known failure before transport, sequence still live | Stay `reserved`; an error label is not finality proof. |
| Later count with incomplete, unauthenticated, or conflicting history | Stay blocked, including after restart and restore. |
| Independently proved non-execution plus stale original sequence and signed decision | Durable terminal tombstone; a different proposal may proceed, original ID never may. |
| Reviewer, plan, deployment, attempt, or checkpoint substitution | Reject without changing the journal. |
| Crash during proof check, tombstone write, or archive rotation | Reopen to either the prior reservation or the complete terminal record; never an empty or replayable state. |
| Multi-process concurrent recovery and submission | Exactly one locked transition; no broadcast until its durable completion. |

Tests using an injected ledger or Compact simulator can validate these
mechanics but cannot close the local RC gate. The final acceptance run needs
the approved deployed local ledger, authentic finalized history, raw private
evidence, and independent human security review under #232.
