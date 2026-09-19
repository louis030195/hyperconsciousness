<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# Mission and scope evals

Keep HC useful as independent private context infrastructure without turning it
into an agent runtime, client app or source-specific backend. Preserve useful
in-scope changes too: rejecting everything is not success.

## Run the fast checks

```sh
npm run eval:scope
```

Requires Node 20+ and git history (`git fetch --unshallow` for a shallow clone).
No API key, network call, model invocation, private brain, or new dependency is
needed. CI runs this as **mission scope (structural)** on every PR and main push.
It does not change branch-protection settings or merge decisions.

The command runs mutation/calibration tests and checks:

- No bundled client/application trees in the declared external roots. The
  website, existing mobile APIs and operating skills remain allowed.
- Library module and runtime-dependency additions against a reviewed inventory.
  Additions may be justified; the tripwire forces that boundary change to be
  visible. Version-only dependency updates and dev-only test tools are allowed.
- Balanced case coverage, unique cases and content hashes for historical anchors
  and the frozen baseline.

These are narrow checks on the current module/manifest shapes, not a Rust/TOML
compiler or semantic code audit. They cannot detect every new responsibility
hidden in an existing file, provider call through an existing HTTP library, or
misleading product claim. Compilation/security tests and actual diff review
remain necessary. Changes to the mission, inventory, graders or CI itself must
be called out in the PR; passing the modified check is not independent approval.

## Historical evidence

`history.json` pins eight public commit/path/blob hashes. CI reads the actual git
objects and verifies them rather than trusting commit titles. Public history
starts at the developer-alpha release; this suite does not invent an earlier
client-removal history. Cases are synthetic scenarios grounded in those
contracts, not claims that every described failure happened.

| Anchor | Boundary used in the cases |
| --- | --- |
| `770a212` | Engine/CLI/skills release; append-only storage, separate clients, no consensus/token requirement |
| `6dfef7f` | Approval client behavior belongs to the external client; server APIs cannot claim its storage guarantees |
| `e66d1c9` | Company membership/device proof is an authority feature, not a CRM product |
| `428e81a` | Hybrid archive compatibility belongs to a source adapter; a backup is not searchable capture |
| `5e5f60d` | Bounded citable context; harnesses retain model/execution/context-assembly ownership |
| `55656f2` | Generic capture/handoffs, source claims and permission-preserving references |
| `7918220` | Retry recovery and current versions with explicit offline and retention limits |

`baseline.json` pins the pre-eval instruction sources and commit. Git retains
the rollback copy; the new AGENTS.md did not exist at that baseline. This records
what was available, not proof that a past agent actually saw it. Some older PRD
positioning was Screenpipe-centric; the current user-directed independent
mission is explicit in MISSION.md and the reconciled PRD.

## Evaluate an agent's scope decisions

The 24 cases exercise six decisions: `in_repo` (generic HC capabilities/APIs or
development work), `adapter` (source/transport-specific work), `external`
(client/harness product), `no_change` (already satisfied/redundant),
`needs_evidence` (a missing measurement/proof prevents a decision), and `reject`
(the proposed mechanism or guarantee violates the mission).

The regression group preserves known product boundaries, not a claim of prior
model pass rates. Capability cases probe nearby tempting expansions. Evaluate
them separately; do not promote either group on fixture scores.

```sh
node evals/scope/run.mjs export /absolute/path/to/new-trial-directory
```

The new directory contains `candidate.json`: the exact instruction hashes,
commit, output contract and tasks, without oracle answers. Run each task in a
fresh instance of the caller's existing harness with that packet's instructions.
Do not give the candidate `cases.json`, this test file, grader oracle, prior
trial answers, or a repo mount containing them. This is a plan/scope-decision
eval, not proof of coding behavior. For implementation trials, use isolated
checkouts and grade the resulting diff and tests with the same rubric.

After the candidate finishes, a separate human or model reviewer reads its
output, [RUBRIC.md](RUBRIC.md), and the case oracle. Preserve the output and review
in a JSON report with:

- `schema: 1`, one `basis` (`fixture`, `model_trial`, or `real_review`), the
  exported `instruction_sha256` and `suite_sha256`, `commit`, `model`, `harness`,
  `budget`, and `reviewer`. Use the current evaluated commit; scoring refuses a
  different checkout or instruction/grader version. These fields are recorded
  provenance, not authentication or proof that a model actually ran.
- `trials`: unique `trial_id`, a `case_id`, and `status` (`completed` or
  `infrastructure_error`). Repeated trials use distinct IDs.
- Completed trials contain `output` with `decision`, `plan`, `boundaries`, and
  `validation`; `output_sha256` is SHA-256 of `JSON.stringify(output)` in field
  order, binding the reviewed artifact.
- `review` has `outcome`, `ownership`, `minimality`, `boundaries`, and `evidence`.
  Each has `verdict: pass|fail|unknown` and an exact `quote` from the candidate
  for pass/fail. Unknowns need no invented supporting quote. The reviewer must
  apply the case's substantive criteria, not just its destination label.

```sh
node evals/scope/run.mjs score /absolute/path/to/reviewed-trials.json
```

The scorer validates artifact bindings, destination decisions and evidence
excerpts, then aggregates **reviewer-supplied semantic judgments**. It is not an
LLM judge or an automatic classifier of arbitrary PRs. A route label alone
cannot pass; a failed dimension cannot be averaged away. Missing cases, unknowns
and infrastructure errors remain visible and cannot yield a complete-suite pass.
Decision-level counts expose accept-all/reject-all optimization; regression and
capability counts remain separate. No fabricated
fixture is evidence of agent performance.

Keep trials under ignored `evals/scope/runs/` or outside the repository. No
private customer transcripts, credentials or personal brain exports in fixtures.
Match model, harness, repo revision and budget when comparing instruction
variants. Inspect traces and repeat trials before interpreting a change. Real
PR reviews use the rubric on their actual diff, not a forced case-bank label.

## Maintenance and sources

Turn a confirmed scope mistake or user correction into a sanitized case plus a
neighbor that must still succeed. Keep a known-good reference and a known-bad
response when calibrating a new judge. Do not rewrite expected answers merely
to make a candidate pass. Use existing owner review for deliberate mission
changes and audit any affected cases.

This design applies three pieces of published Anthropic guidance:

- [Demystifying evals for AI agents](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents): start with real cases, balance positive/negative behavior, grade outcomes, calibrate judges, isolate trials and retain unknowns. The mutation tests and score fixtures here are grader calibration; no model trials have been run by CI.
- [Building effective agents](https://www.anthropic.com/engineering/building-effective-agents): begin with simple composable mechanisms and justify additional complexity. This dev-only suite adds no orchestration runtime to HC.
- [Effective context engineering](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents): keep tool responsibilities clear, use bounded context and progressive retrieval, and avoid overlapping tool surfaces.
