// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com
import { localRequest } from "@/lib/model";
import { readRecords, recordRequest, ReaderBusy } from "@/lib/records";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  const reply = (value: unknown, status = 200) =>
    Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
  if (!localRequest(request.headers))
    return reply({ error: "Local dashboard requests only" }, 403);
  let input;
  try {
    const reader = request.body?.getReader();
    if (!reader) return reply({ error: "Request required" }, 400);
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 4096) {
        await reader.cancel();
        return reply({ error: "Request too large" }, 413);
      }
      chunks.push(value);
    }
    input = recordRequest(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  } catch {
    return reply({ error: "Invalid record request" }, 400);
  }
  try {
    return reply(await readRecords(input));
  } catch (error) {
    if (error instanceof ReaderBusy)
      return reply(
        {
          error:
            "The HC reader is temporarily busy or unavailable. Try again after it finishes updating.",
          retryable: true,
        },
        503,
      );
    const configured = Boolean(
      process.env.HC_DASHBOARD_MCP_URL &&
      process.env.HC_DASHBOARD_MCP_TOKEN_FILE,
    );
    return reply(
      {
        error: configured
          ? "The HC reader could not complete this request. Access may have expired, the reader may be busy, or the response format may be unsupported. Try again."
          : "Record browsing needs an authenticated HC reader. Configure it on the dashboard server; storage inspection remains available.",
      },
      503,
    );
  }
}
