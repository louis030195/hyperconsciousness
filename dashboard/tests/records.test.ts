// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com
import { expect, test } from "bun:test";
import { recordRequest, searchPage, retryableStatus } from "../lib/records";
test("record input only permits bounded reader arguments", () => {
  expect(recordRequest({ query: "google ads", cursor: "opaque" })).toEqual({
    query: "google ads",
    cursor: "opaque",
  });
  for (const input of [
    null,
    [],
    { tool: "remember" },
    { query: "a".repeat(201) },
    { ref: "../secret" },
    { ref: "abcdef123456:1", query: "x" },
    { cursor: 4 },
  ])
    expect(() => recordRequest(input)).toThrow();
});
test("reader errors and unsupported contracts never become empty results", () => {
  for (const result of [
    {},
    { isError: true },
    { content: [] },
    { content: [{ type: "text", text: "unknown response" }] },
    { structuredContent: { schema: "hc.context.v1", items: [] } },
  ])
    expect(() => searchPage(result)).toThrow();
  expect(
    searchPage({
      content: [{ type: "text", text: "nothing in this grant matched\n" }],
    }).items,
  ).toEqual([]);
});
test("filtered search preserves citations, dates and opaque continuation", () => {
  const result = searchPage({
    content: [
      {
        type: "text",
        text: "2026-09-24  [abcdef123456:1]  older\n2026-09-25  [abcdef123456:2]  <script>not executable</script>\n\n2 excerpts clipped; call record with a result ref for full content\nnext_cursor: opaque",
      },
    ],
  });
  expect(result.nextCursor).toBe("opaque");
  expect(result.items[0]).toEqual({
    ref: "abcdef123456:2",
    text: "<script>not executable</script>",
    ingestedDay: "2026-09-25",
  });
  expect(result.items[1].ref).toBe("abcdef123456:1");
});
test("withdrawn text never falls back to unfiltered structured excerpts", () => {
  const notice = "Source access withdrawn; historical content withheld.";
  const result = searchPage({
    content: [{ type: "text", text: notice + "\nnext_cursor: opaque" }],
    structuredContent: {
      schema: "hc.context.v1",
      items: [
        {
          ref: "abcdef123456:1",
          text: "WITHDRAWN SECRET",
          ingested_at_ms: 1000,
        },
      ],
    },
  });
  expect(result.items).toEqual([]);
  expect(result.notices).toEqual([notice]);
  expect(JSON.stringify(result)).not.toContain("SECRET");
  expect(result.nextCursor).toBe("opaque");
});
test("superseded and incomplete source notices stay visible", () => {
  const notices = [
    "Source part withheld: its parent version is incomplete, replaced or retired.",
    "Historical source content suppressed. Current observed record: abcdef123456:2. Reopen with record.",
  ];
  const result = searchPage({
    content: [{ type: "text", text: notices.join("\n") }],
  });
  expect(result.notices).toEqual(notices);
  expect(result.items).toEqual([]);
});

test("maintenance is retryable but authorization denials are not", () => {
  for (const code of [429, 502, 503, 504])
    expect(retryableStatus(code)).toBe(true);
  for (const code of [400, 401, 403, 404])
    expect(retryableStatus(code)).toBe(false);
});
