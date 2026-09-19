<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# Working on HC

Read [MISSION.md](MISSION.md) and the relevant existing contract before planning
a change. Keep HC independent of Screenpipe and of any agent harness. Complete
the user's requested outcome with the smallest justified implementation; do not
add adjacent product features or block legitimate work merely to minimize code.
A verified no-change result is valid when the request is already satisfied.

Run `npm run eval:scope` for repository boundary checks and evaluator tests, plus
the implementation checks in CONTRIBUTING.md appropriate to the change. These
checks cannot prove semantic mission alignment. Review the actual diff using
[the scope rubric](evals/scope/RUBRIC.md), state limitations, and include the
mission fit and relevant regression evidence in the PR. Do not change the
charter, policy inventory or expected answers just to make an unrelated patch
pass. Keep model trials and private transcripts out of committed fixtures.
