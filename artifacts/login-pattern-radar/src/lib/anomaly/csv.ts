import type { LoginEvent } from "./types";

export const MAX_CSV_ROWS = 50_000;

function parseLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  out.push(cur);
  return out.map((c) => c.trim());
}

const TRUE_VALUES = new Set(["true", "1", "yes", "success", "ok"]);
const FALSE_VALUES = new Set(["false", "0", "no", "fail", "failed", "failure"]);

/** Parses CSV with columns: user_id, timestamp, location, success. Throws a readable Error on bad input. */
export function parseLoginCsv(text: string): LoginEvent[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) throw new Error("The CSV needs a header row and at least one login.");
  const header = parseLine(lines[0]!).map((h) => h.toLowerCase());
  const col = (name: string) => header.indexOf(name);
  const iu = col("user_id");
  const it = col("timestamp");
  const il = col("location");
  const is = col("success");
  if ([iu, it, il, is].some((i) => i < 0)) {
    throw new Error("CSV header must include: user_id, timestamp, location, success");
  }
  if (lines.length - 1 > MAX_CSV_ROWS) throw new Error(`CSV is limited to ${MAX_CSV_ROWS.toLocaleString()} rows.`);

  const events: LoginEvent[] = [];
  for (let n = 1; n < lines.length; n++) {
    const cells = parseLine(lines[n]!);
    const userId = cells[iu] ?? "";
    const ts = cells[it] ?? "";
    const location = cells[il] ?? "";
    const successRaw = (cells[is] ?? "").toLowerCase();
    const parsed = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(ts) ? ts : `${ts.replace(" ", "T")}Z`);
    if (!userId || Number.isNaN(parsed)) throw new Error(`Row ${n + 1}: missing user_id or unreadable timestamp.`);
    if (!TRUE_VALUES.has(successRaw) && !FALSE_VALUES.has(successRaw)) {
      throw new Error(`Row ${n + 1}: success must be true/false (got "${cells[is] ?? ""}").`);
    }
    events.push({
      id: `row_${n}`,
      userId: userId.slice(0, 120),
      timestamp: new Date(parsed).toISOString(),
      location: (location || "unknown").slice(0, 120),
      success: TRUE_VALUES.has(successRaw),
      label: null,
    });
  }
  if (!events.some((e) => e.success)) throw new Error("The CSV has no successful logins to score.");
  return events;
}
