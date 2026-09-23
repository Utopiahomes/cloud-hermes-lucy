# Personal Lucy memory retrieval and interpretation v2 — proposal

Status: design proposal, 2026-09-23. No migration, provider change, candidate
promotion, or production activation is authorized by this document.

## Why the current pilot is insufficient

The `Gate` Telegram test exposed two distinct failures. The gateway searched
only the quoted topic `Gate` even though the question also asked about
`Magician`. Lucy then treated a missing retrieval result as evidence that no
Magician memory existed, although two reviewed interpretations do exist. It
also called a historical minimum tag “re-confirmed” in the present, while the
reviewed record marks present applicability `not_checked`.

This cannot be solved reliably by adding more words to the prompt or by
raising the result limit. The current protected SQL search matches one literal
substring in claim subject, predicate, or serialized object, then sorts by
stored confidence and creation time and returns at most five. It does not
plan coverage across a multi-part question, rank semantic relevance, traverse
related concepts, or distinguish a limited search from evidence of absence.
Each mapped interpretation also assigns citation labels starting at `E1`, so
labels can collide when multiple interpretations enter one answer packet.
The earlier 32-item local probe and 13-question shadow evaluation remain useful
gold cases, but neither proves retrieval at larger scale.

## Memory contract

Keep three distinct layers in Raymond's logical database:

1. **Source evidence:** encrypted original turns, role, date, scope, consent,
   and deletion lineage. Source material is never silently rewritten to make a
   later interpretation look older or more certain.
2. **Versioned interpretations:** one proposition or relationship per record,
   with entity/topic links; who proposed and confirmed which portion; source
   support and counterevidence; historical validity and current applicability;
   remembering value; supersession and correction links. A new reading appends
   a version with a reason and source references. No single “percent true”
   replaces these independent dimensions.
3. **Working answer packet:** a disposable, question-specific selection from
   the authorized interpretations and evidence. It records which parts of the
   question were searched, which were supported or unresolved, and one unique
   citation map for the entire answer.

The archive is evidence, not Lucy's current opinion. The latest interpretation
is a revisable reading, not a replacement for the older one. A correction can
lower current applicability while retaining the past statement and why it was
once plausible. Deletion remains a separate owner-governed operation and must
invalidate every derived index and answer path.

## Retrieval and answer flow

1. **Plan the question.** Extract requested topics, entities, relationships,
   time frame, and whether the owner asks for a historical account or present
   view. In the failing example, `Gate` and `Magician` are two required topics.
   A bounded planner may suggest expansions, but the policy service must
   validate and cap them. A failed planner falls back to conservative literal
   searches and reports limited coverage.
2. **Find candidates per topic.** Combine exact names and aliases, PostgreSQL
   full-text search, and a later optional semantic index in the same Raymond
   logical database. Expand only a small number of provenance-linked neighbors
   (e.g., a tag, card, decision, and its correction). Apply scope, consent,
   deletion, status, and owner-event checks before any candidate can be
   returned. Fuse results and rerank for relevance; confidence is evidence
   quality, not a substitute for question relevance.
3. **Check coverage and disagreement.** Reserve a bounded result quota for
   each requested topic. Include the relevant current version, historical
   version when asked, and any material contradiction or supersession. A zero
   result means “not found in this search,” never “it never existed.” Search
   expansion may run once within a time/cost cap; unresolved topics remain
   explicitly unresolved.
4. **Build one evidence packet.** Deduplicate claims and sources; assign
   unique `E1`, `E2`, ... labels across the whole packet; map each label to one
   exact source ID, speaker, date, and relation. Bound both source count and
   token size. Preserve the distinction between an owner statement, an
   assistant suggestion, and the reviewer's interpretation.
5. **Draft and verify.** The model answers from that packet only. A validator
   checks that citation labels exist, required topics are covered or declared
   unresolved, and historical `not_checked` facts are not phrased as current
   confirmations. Unsupported absence and current-status claims cause a retry
   or a short qualified answer, not a confident assertion.

This is retrieval over a controlled interpretation graph, not a large dump of
old conversations into one prompt. PostgreSQL full-text search offers ranking
of textual matches; pgvector can add semantic candidates and supports hybrid
fusion with full-text search if the Raymond deployment supports the extension
and an embedding route is separately approved. Neither index is the source of
authority: the policy and lineage checks remain on the canonical records.

## Revising without hand-editing every old statement

New retained exchanges can trigger candidate interpretations, contradiction
checks, and a proposed revision to a linked older interpretation. Lucy may
automatically identify that a former position is likely stale or that two
sources disagree, but should not silently turn a model inference into Ray's
endorsement. The review queue should group related changes and prioritize
high-impact or low-certainty conflicts so Ray can approve a correction to a
topic, rather than edit every historical sentence. Whether any class of
low-risk revision can apply automatically is a later governance decision;
existing human promotion gates remain in force until changed explicitly.

## First build and acceptance gate

Build this on the reviewed 32 interpretations before broad backfill. First
create a fixed evaluation set from the existing shadow questions plus new
multi-topic, ambiguous-tag, contradiction, current-versus-historical,
limited-search, and deletion cases. Run retrieval without a model first, then
evaluate the full answer path. Include the exact `Gate` + `Magician` question.

The first gate should require:

- Both named topics retrieved, with the Magician's confirmed `Universal Aid`
  decision present and Gate's ambiguous second tag preserved.
- No current endorsement inferred from a `not_checked` historical memory.
- Every displayed citation label unique within the answer and mapped to the
  exact authorized source; no label attached to an unsupported claim.
- A missing result described as limited retrieval, not proof of nonexistence.
- Deletion-fenced evidence excluded from lexical, semantic, graph, cached,
  and answer-packet paths.
- Bounded latency, tokens, source disclosures, and provider cost recorded
  against the existing Raymond budget and owner interaction.

Run the same set after adding more of the already ingested history and at
several simulated corpus sizes. Promote/backfill only when accuracy and cost
stay within the agreed thresholds. The current Telegram recall should be
treated as an experimental pilot until this gate passes; do not expand import
or reinterpret the rest of the 474 archived source records merely to make the
small test look complete. The 32 interpretations and 474 source records are
different units, not one-to-one entries.

## Implementation order

1. Freeze the evaluation examples and expected source IDs from the protected
   review, including the failed live answer. Keep private text out of Git.
2. Add query planning, topic coverage, and one global citation map behind a
   read-only Raymond policy API. Start with existing PostgreSQL facilities;
   establish a measured baseline before adding embeddings.
3. Add version/relationship retrieval and deterministic answer validation.
   Exercise correction and deletion invalidation in a local isolated store.
4. Shadow the new path against the current pilot without changing the live
   bot, then roll it out to Raymond Telegram with a reversible feature flag.
5. Only after the first gate passes, stage reinterpretation of older imported
   records in reviewable batches and measure quality as the corpus grows.

References for implementation options: [PostgreSQL full-text search](https://www.postgresql.org/docs/current/textsearch.html),
[pgvector hybrid search guidance](https://github.com/pgvector/pgvector#hybrid-search),
and [Lost in the Middle](https://arxiv.org/abs/2307.03172), which motivates
keeping the answer packet selective rather than simply lengthening prompts.
