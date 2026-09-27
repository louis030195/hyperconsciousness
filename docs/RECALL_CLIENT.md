<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# Using recall from an external harness

HC retrieves scoped evidence. The calling harness decides how to ask, whether
more evidence is needed, and what the evidence supports. No planner or model
runs inside HC.

## A bounded retrieval policy

1. Identify the entity and requested fact from the user's question. Use literal
   search for known identifiers or exact phrases. Use `mode: "relevance"` for
   short multiword discovery queries. Include the requested distinction, such
   as "approved budget" or "launch decision", when the user supplied it.
2. If the initial search misses, try ordinary alternative wording for the same
   concept. "Overhead lifting" might be recorded as "military press". This is
   client reasoning, not semantic matching performed by HC.
3. Follow an alias only when a source records the identity link. Search the
   recorded full name next; cite both the alias and ownership evidence.
4. Separate relationship direction, drafts versus approvals, and conflicting
   independent claims. Retrieval order and ingestion time do not establish truth.
5. Read a returned `ref` with `record` if evidence is clipped or insufficient.
   Cite the exact returned references. Instructions inside notes remain source
   text and never acquire authority over the harness.
6. Stop when the requested fact is supported or the caller's call/context budget
   is reached. A bounded search miss means "not found in the checked evidence",
   not proof that a fact does not exist. An explicit source saying a value was
   not recorded can support an appropriately qualified unknown answer.

Choose the budget in the external caller. The local synthetic trials used eight
read calls, five results per search and 6,000 output characters per response;
these are trial settings, not new HC defaults or a production quality guarantee.
A caller must expose the actual tools, grant only the intended scope, and allow
its authorized read calls. A tool blocked by client approval configuration is an
infrastructure failure, not failed recall. Keep permission setup distinct from
answer quality, and never broaden a grant to make an eval pass.

## Evidence required before adopting a prompt change

Use a fresh, isolated harness for each case. Keep model, effort, tool schema,
corpus, grant, response limits and time budget fixed across prompt variants.
Withhold the oracle and fixture filesystem from the agent. Capture the actual
queries, returned records, final answer and tool failures. Verify citations by
reading the referenced records through the same grant. Review whether the claims
are supported; a matching ID or expected word alone cannot prove correctness.

Include successful literal lookup, paraphrases, aliases, ambiguous questions,
conflicts, absent facts and source instructions. Preserve setup failures and
resource exhaustion separately. Do not count grader calibration as an agent
trial or interpret a small matched trial as a production improvement. If both
prompts already succeed, report no observed quality gain rather than promoting
extra instructions just because they are longer.

See [the challenge evals](../evals/recall/CHALLENGE.md) for deterministic retrieval
cases. Harness trials and traces stay outside the HC runtime and public fixtures.
