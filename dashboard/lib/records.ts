// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com
import { request as httpsRequest } from "node:https";
import { lstat, readFile } from "node:fs/promises";

export class ReaderBusy extends Error {}
export function retryableStatus(status: number) {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

export type RecordRequest = { query?: string; cursor?: string; ref?: string };
export function recordRequest(input: unknown): RecordRequest {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw Error("Invalid request");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((k) => !["query", "cursor", "ref"].includes(k)))
    throw Error("Invalid request");
  for (const [key, max] of [
    ["query", 200],
    ["cursor", 1024],
    ["ref", 100],
  ] as const) {
    if (
      value[key] !== undefined &&
      (typeof value[key] !== "string" || (value[key] as string).length > max)
    )
      throw Error("Invalid request");
  }
  if (
    value.ref !== undefined &&
    (!/^[a-f0-9]{12,64}:\d+$/.test(value.ref as string) ||
      value.query !== undefined ||
      value.cursor !== undefined)
  )
    throw Error("Invalid record reference");
  return value as RecordRequest;
}
async function boundedFile(path: string, max: number) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > max)
    throw Error("Reader configuration unavailable");
  return readFile(path, "utf8");
}
export function searchPage(result: any) {
  // Company readers apply source withdrawal/version checks to text blocks.
  // Never recover excerpts from structuredContent: it may precede those checks.
  if (
    result?.isError ||
    !Array.isArray(result?.content) ||
    !result.content.length
  )
    throw Error("Unsupported reader response");
  const items: { ref: string; text: string; ingestedDay: string }[] = [];
  const notices: string[] = [];
  let nextCursor: string | undefined;
  let recognized = false;
  for (const block of result.content) {
    if (block.type !== "text" || typeof block.text !== "string")
      throw Error("Unsupported reader response");
    for (const line of block.text
      .split("\n")
      .map((v: string) => v.trim())
      .filter(Boolean)) {
      const row =
        /^(\d{4}-\d{2}-\d{2})\s+\[([a-f0-9]{12,64}:\d+)\]\s*(.*)$/.exec(line);
      if (row) {
        if (row[3].length > 2000 || items.length >= 20)
          throw Error("Invalid record");
        items.push({ ingestedDay: row[1], ref: row[2], text: row[3] });
      } else if (line.startsWith("next_cursor: ")) {
        if (nextCursor || line.length > 1037) throw Error("Invalid cursor");
        nextCursor = line.slice("next_cursor: ".length);
      } else if (
        line === "Source access withdrawn; historical content withheld." ||
        line ===
          "Source part withheld: its parent version is incomplete, replaced or retired." ||
        /^Historical source content suppressed\. Current observed record: (?:[a-f0-9]{12,64}:\d+|undefined)\. Reopen with record\.$/.test(
          line,
        )
      ) {
        notices.push(line);
      } else if (
        line !== "nothing in this grant matched" &&
        !/^\d+ excerpts clipped; call record with a result ref for full content$/.test(
          line,
        ) &&
        !/^response budget limited this call to \d+ results; raise max_output_chars for more$/.test(
          line,
        )
      ) {
        throw Error("Unsupported reader response");
      }
      recognized = true;
    }
  }
  if (!recognized) throw Error("Unsupported reader response");
  return {
    items: items.reverse(),
    notices: [...new Set(notices)],
    nextCursor,
    hasMore: !!nextCursor,
  };
}
let active = 0;
export async function readRecords(input: RecordRequest) {
  const endpoint = process.env.HC_DASHBOARD_MCP_URL;
  const tokenPath = process.env.HC_DASHBOARD_MCP_TOKEN_FILE;
  if (!endpoint || !tokenPath)
    throw Error("Configure an authenticated HC reader to browse records.");
  const url = new URL(endpoint);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    url.search
  )
    throw Error("Reader must use HTTPS");
  if (active >= 2) throw new ReaderBusy("Reader is busy");
  active++;
  try {
    // Operator configuration only. Credentials never enter browser responses.
    const token = (await boundedFile(tokenPath, 4096)).trim();
    const ca = process.env.HC_DASHBOARD_MCP_CA_FILE
      ? await boundedFile(process.env.HC_DASHBOARD_MCP_CA_FILE, 65536)
      : undefined;
    const name = input.ref ? "record" : "search";
    const args = input.ref
      ? { ref: input.ref, max_chars: 6000 }
      : {
          query: input.query || "",
          ...(input.cursor ? { cursor: input.cursor } : {}),
          format: "text",
          limit: 3,
          max_chars: 800,
          max_output_chars: 6000,
        };
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    });
    const value: any = await new Promise((resolve, reject) => {
      const req = httpsRequest(
        url,
        {
          method: "POST",
          ca,
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            Accept: "application/json",
            "Content-Length": Buffer.byteLength(payload),
          },
        },
        (res) => {
          let size = 0;
          const parts: Buffer[] = [];
          res.on("data", (chunk) => {
            size += chunk.length;
            if (size > 256 * 1024) {
              req.destroy(Error("Reader response too large"));
              return;
            }
            parts.push(chunk);
          });
          res.on("error", reject);
          res.on("end", () => {
            if (res.statusCode !== 200) {
              reject(
                retryableStatus(res.statusCode || 0)
                  ? new ReaderBusy("Reader temporarily unavailable")
                  : Error("Reader denied or unavailable"),
              );
              return;
            }
            try {
              resolve(JSON.parse(Buffer.concat(parts).toString("utf8")));
            } catch {
              reject(Error("Invalid reader response"));
            }
          });
        },
      );
      const deadline = setTimeout(
        () => req.destroy(new ReaderBusy("Reader timed out")),
        45000,
      );
      req.on("close", () => clearTimeout(deadline));
      req.on("error", reject);
      req.end(payload);
    });
    if (value.error || value.result?.isError)
      throw Error("Reader denied or unavailable");
    if (!input.ref) return searchPage(value.result);
    if (!Array.isArray(value.result?.content))
      throw Error("Invalid record response");
    const text = value.result.content
      .filter((v: any) => v.type === "text" && typeof v.text === "string")
      .map((v: any) => v.text)
      .join("\n");
    return {
      ref: input.ref,
      text: text.slice(0, 12000),
      clipped: text.length > 12000,
    };
  } finally {
    active--;
  }
}
