<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# Recall challenge cases

This is a synthetic challenge set written after lexical relevance implementation
`15da246`, frozen before its first execution. It is not an independently authored
blind holdout. Do not tune retrieval on these cases and then claim a held-out
improvement. Keep the original suite and all first-run baselines intact.

```sh
npm run eval:challenge -- --gate=contracts
npm run eval:challenge
```

There are 17 distinct scenarios and 15 reversed-insertion variants. Each contains
24 fixed distractors plus its focal records. Causal managed revisions are not
reversed, because that would change their meaning. Cases exercise:

- Explicit decision and approval intent, included in the query itself.
- No-overlap paraphrases, alias chains and relationship direction.
- Missing values versus incidental numbers, and instructions embedded in notes.
- Multiple constraints, explicit conflicts and distinct projects with similar names.
- Negation, exact identifiers, absent topics, private records, corrections and retractions.

The expected ID sets allow any order where the task needs several independent
pieces of evidence. Insertion variants additionally require the same returned
ordering. This keeps completeness distinct from arbitrary ordering preferences.
The frozen older exact-order oracles are unchanged.

The first executed baseline is `challenge-baseline.json`: 14/14 contracts and
4/18 capability variants passed across scan, snapshot and indexed reads, with
zero infrastructure errors. The four passes represent the two explicit-intent
scenarios in both insertion orders. Fourteen unmet capability variants remain
failures. `--gate=contracts` reports these failures while gating only implemented
contracts and infrastructure. The all-outcome command must fail until they pass.

Reports separate category-level strict outcomes and complete-evidence diagnostics.
A noisy result can contain the required evidence and still fail strict selection.
Neither diagnostic establishes correct answering, alias resolution, abstention,
or instruction resistance by an agent. For example, the source-instruction case
checks retrieval selection only; resistance requires an actual harness trial.

Only synthetic fixture text and compact baseline results are committed. Model
traces, actual user data, credentials, local stores and environment-specific trial
configuration do not belong in these fixtures. The external client guidance is
in [RECALL_CLIENT.md](../../docs/RECALL_CLIENT.md).
