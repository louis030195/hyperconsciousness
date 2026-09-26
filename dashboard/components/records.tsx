// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com
"use client";
import { useEffect, useRef, useState } from "react";
import { Search, RefreshCw } from "lucide-react";
type Entry = {
  ref: string;
  text: string;
  ingestedDay: string;
};
type Page = {
  notices?: string[];
  items: Entry[];
  nextCursor?: string;
  hasMore: boolean;
};
async function read(input: object, signal: AbortSignal) {
  const response = await fetch("/api/records", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-HC-Dashboard": "1" },
    body: JSON.stringify(input),
    cache: "no-store",
    signal,
  });
  const result = await response.json();
  if (!response.ok)
    throw Object.assign(Error(result.error || "Reader unavailable"), {
      retryable: result.retryable === true,
    });
  return result;
}
export function Records({ revision }: { revision: number }) {
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState("");
  const [cursors, setCursors] = useState<string[]>([""]);
  const [page, setPage] = useState<Page>();
  const [loading, setLoading] = useState(true);
  const [loadingText, setLoadingText] = useState("Reading records…");
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [detail, setDetail] = useState<{ ref: string; text: string }>();
  const detailRequest = useRef<AbortController | null>(null);
  const cursor = cursors[cursors.length - 1];
  useEffect(() => {
    let current = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 55000);
    setLoading(true);
    setLoadingText("Reading records…");
    setError("");
    setPage(undefined);
    setDetail(undefined);
    detailRequest.current?.abort();
    (async () => {
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          return await read(
            { query, ...(cursor ? { cursor } : {}) },
            controller.signal,
          );
        } catch (e) {
          if (
            !(e as { retryable?: boolean }).retryable ||
            attempt === 3 ||
            controller.signal.aborted
          )
            throw e;
          if (current)
            setLoadingText(
              `Reader temporarily busy. Retrying (${attempt + 1}/3)…`,
            );
          await new Promise((resolve) => setTimeout(resolve, 2000));
          if (controller.signal.aborted) throw e;
        }
      }
    })()
      .then((value) => {
        if (current) setPage(value);
      })
      .catch((e) => {
        if (!current) return;
        if (!controller.signal.aborted) setError(e.message);
        else setError("The reader took too long. Try again.");
      })
      .finally(() => {
        clearTimeout(timeout);
        if (current) setLoading(false);
      });
    return () => {
      current = false;
      controller.abort();
      clearTimeout(timeout);
    };
  }, [query, cursor, revision, retry]);
  useEffect(() => () => detailRequest.current?.abort(), []);
  async function open(ref: string) {
    detailRequest.current?.abort();
    if (detail?.ref === ref) {
      setDetail(undefined);
      return;
    }
    const controller = new AbortController();
    detailRequest.current = controller;
    const timeout = setTimeout(() => controller.abort(), 50000);
    setDetail({ ref, text: "Loading record…" });
    try {
      const result = await read({ ref }, controller.signal);
      if (!controller.signal.aborted)
        setDetail({
          ref,
          text: result.text + (result.clipped ? "\n[Preview truncated]" : ""),
        });
    } catch (e) {
      if (detailRequest.current === controller)
        setDetail({
          ref,
          text: controller.signal.aborted
            ? "The reader took too long. Close and retry."
            : (e as Error).message,
        });
    } finally {
      clearTimeout(timeout);
    }
  }
  return (
    <>
      <div className="page-heading">
        <span className="eyebrow">HC ATLAS / 05</span>
        <h1>
          Your <em>records.</em>
        </h1>
        <p>
          Browse notes and imported source records available to this dashboard’s
          HC reader.
        </p>
      </div>
      <section className="panel records-panel">
        <div className="section-head">
          <div>
            <span className="eyebrow">KNOWLEDGE / READER ACCESS</span>
            <h2>{query ? "Search results" : "Recent records"}</h2>
          </div>
          <button
            className="text-button"
            disabled={loading}
            onClick={() => setRetry((n) => n + 1)}
          >
            <RefreshCw size={15} /> Refresh records
          </button>
        </div>
        <form
          className="records-search"
          onSubmit={(event) => {
            event.preventDefault();
            setCursors([""]);
            setQuery(draft.trim());
            setRetry((n) => n + 1);
          }}
        >
          <label className="search-field">
            <Search size={18} />
            <input
              id="record-search"
              aria-label="Search records"
              placeholder="Search company records…"
              value={draft}
              maxLength={200}
              onChange={(e) => setDraft(e.target.value)}
            />
          </label>
          <button className="primary-button" disabled={loading} type="submit">
            Search
          </button>
          {query && (
            <button
              className="text-button"
              type="button"
              onClick={() => {
                setDraft("");
                setQuery("");
                setCursors([""]);
              }}
            >
              Clear search
            </button>
          )}
        </form>
        <p className="panel-footnote">
          Search uses your reader’s current grant. Results can include
          historical source versions. Dates below show HC ingestion, not when
          the original event happened.
        </p>
        <div aria-live="polite">
          {loading && <p className="empty-copy">{loadingText}</p>}
          {error && (
            <div role="alert" className="notice">
              {error}{" "}
              <button
                className="text-button"
                onClick={() => setRetry((n) => n + 1)}
              >
                Try again
              </button>
            </div>
          )}
        </div>
        {page && (
          <>
            {page.notices?.map((notice) => (
              <p className="notice" key={notice}>
                {notice}
              </p>
            ))}
            {page.items.length === 0 && (
              <p className="empty-copy">
                No records matched within this reader’s access. This does not
                mean the store is empty.
              </p>
            )}
            <div className="record-list">
              {page.items.map((item) => {
                const source = /Source:\s+(.+?)\s+Source ID:/.exec(
                  item.text,
                )?.[1];
                const excerpt = item.text.replace(
                  /^Content SHA256: [a-f0-9]+\s+Source identity SHA256: [a-f0-9]+\s*/,
                  "",
                );
                return (
                  <article className="record-card" key={item.ref}>
                    <div className="record-meta">
                      <code>{item.ref}</code>
                      <span>Ingested {item.ingestedDay}</span>
                    </div>
                    <h3>{source || "Stored record"}</h3>
                    <p className="record-excerpt">{excerpt}</p>
                    <button
                      className="text-button"
                      aria-expanded={detail?.ref === item.ref}
                      aria-controls={`record-${item.ref}`}
                      onClick={() => void open(item.ref)}
                    >
                      {detail?.ref === item.ref
                        ? "Close record"
                        : "Read record"}
                    </button>
                    {detail?.ref === item.ref && (
                      <pre id={`record-${item.ref}`} className="record-body">
                        {detail.text}
                      </pre>
                    )}
                  </article>
                );
              })}
            </div>
            <div className="table-footer">
              <span>
                {page.items.length} results · Page {cursors.length} · Previews
                may be clipped
              </span>
              <div>
                <button
                  className="text-button"
                  disabled={cursors.length === 1 || loading}
                  onClick={() => setCursors((v) => v.slice(0, -1))}
                >
                  Previous
                </button>
                <button
                  className="text-button"
                  disabled={!page.nextCursor || loading}
                  onClick={() => {
                    if (page.nextCursor)
                      setCursors((v) => [...v, page.nextCursor!]);
                  }}
                >
                  Older results
                </button>
              </div>
            </div>
            {page.hasMore && !page.nextCursor && (
              <p className="panel-footnote">
                The reader reports more results but supplied no continuation
                cursor. Narrow your search.
              </p>
            )}
          </>
        )}
      </section>
    </>
  );
}
