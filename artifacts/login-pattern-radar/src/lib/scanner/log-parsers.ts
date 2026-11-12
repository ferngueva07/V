import type { LoginEvent } from "../anomaly/types";

export type LogFormat = "login-csv" | "windows-security" | "json" | "auth-log";

export interface ParsedLog {
  format: LogFormat;
  events: LoginEvent[];
  /** Records that looked like log entries but lacked a user, time, or outcome. */
  skipped: number;
}

const MAX_EVENTS = 50_000;

/** Splits CSV text into rows, honouring quoted fields that may contain commas or newlines. */
export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(cur.trim());
      cur = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(cur.trim());
      if (row.some((c) => c.length)) rows.push(row);
      row = [];
      cur = "";
    } else cur += ch;
  }
  row.push(cur.trim());
  if (row.some((c) => c.length)) rows.push(row);
  return rows;
}

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

const USER_KEYS = ["userid", "user", "username", "accountname", "account", "targetusername", "login", "email", "upn", "userprincipalname"];
const TIME_KEYS = ["timestamp", "time", "datetime", "dateandtime", "date", "eventtime", "createddatetime", "ts", "timecreated", "logintime"];
const LOCATION_KEYS = ["location", "sourcenetworkaddress", "ipaddress", "ip", "sourceip", "srcip", "clientip", "remoteip", "src", "country", "city", "workstationname"];
const SUCCESS_KEYS = ["success", "status", "result", "outcome", "loginresult", "succeeded", "keywords", "eventtype"];
const EVENT_ID_KEYS = ["eventid", "eventcode", "id"];

const TRUE_VALUES = new Set(["true", "1", "yes", "success", "succeeded", "ok", "accepted", "allow", "allowed", "auditsuccess", "pass", "passed"]);
const FALSE_VALUES = new Set(["false", "0", "no", "fail", "failed", "failure", "denied", "deny", "rejected", "auditfailure", "blocked", "error"]);

function findKey(keys: string[], candidates: string[]): string | undefined {
  const normalized = keys.map(norm);
  for (const c of candidates) {
    const idx = normalized.indexOf(c);
    if (idx >= 0) return keys[idx];
  }
  return undefined;
}

function parseTime(raw: unknown): number {
  if (typeof raw === "number") return raw < 1e12 ? raw * 1000 : raw;
  if (typeof raw !== "string" || !raw.trim()) return NaN;
  const s = raw.trim();
  if (/^\d{10,13}$/.test(s)) return parseTime(Number(s));
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s.replace(" ", "T")}Z`;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? Date.parse(s) : t;
}

function parseSuccess(raw: unknown): boolean | null {
  if (typeof raw === "boolean") return raw;
  if (raw === null || raw === undefined) return null;
  const v = norm(String(raw));
  if (TRUE_VALUES.has(v)) return true;
  if (FALSE_VALUES.has(v)) return false;
  return null;
}

/** Windows Security logon event IDs: 4624/4648 successful, 4625/4771 failed. */
function successFromEventId(raw: unknown): boolean | null {
  const id = String(raw ?? "").trim();
  if (id === "4624" || id === "4648") return true;
  if (id === "4625" || id === "4771") return false;
  return null;
}

/** Pulls `Account Name:` / `Source Network Address:` fields out of a Windows event message (last non-machine value wins). */
function fromWindowsMessage(message: string): { user?: string; location?: string } {
  const pick = (label: string) => {
    const re = new RegExp(`${label}:[ \\t]*([^\\r\\n\\t]+)`, "gi");
    const values = [...message.matchAll(re)].map((m) => m[1]!.trim()).filter((v) => v && v !== "-" && !v.endsWith("$"));
    return values[values.length - 1];
  };
  return { user: pick("Account Name"), location: pick("Source Network Address") ?? pick("Workstation Name") };
}

function makeEvent(n: number, prefix: string, user: string, time: number, location: string, success: boolean): LoginEvent {
  return {
    id: `${prefix}_${n}`,
    userId: user.slice(0, 120),
    timestamp: new Date(time).toISOString(),
    location: (location || "unknown").slice(0, 120),
    success,
    label: null,
  };
}

const str = (v: unknown) => (v === null || v === undefined ? "" : String(v).trim());

function recordsToEvents(records: Record<string, unknown>[], prefix: string): { events: LoginEvent[]; skipped: number; windows: boolean } {
  const events: LoginEvent[] = [];
  let skipped = Math.max(0, records.length - MAX_EVENTS);
  let windows = false;
  records.slice(0, MAX_EVENTS).forEach((rec, n) => {
    const keys = Object.keys(rec);
    const uk = findKey(keys, USER_KEYS);
    const tk = findKey(keys, TIME_KEYS);
    const lk = findKey(keys, LOCATION_KEYS);
    const sk = findKey(keys, SUCCESS_KEYS);
    const ek = findKey(keys, EVENT_ID_KEYS);
    const messageKey = keys.find((k) => typeof rec[k] === "string" && /Account Name:/i.test(rec[k] as string));
    const winMsg = messageKey ? fromWindowsMessage(rec[messageKey] as string) : {};
    const evSuccess = ek ? successFromEventId(rec[ek]) : null;
    if (evSuccess !== null || messageKey) windows = true;
    const user = (uk ? str(rec[uk]) : "") || winMsg.user || "";
    const location = (lk ? str(rec[lk]) : "") || winMsg.location || "";
    const time = parseTime(tk ? rec[tk] : undefined);
    const success = evSuccess ?? (sk ? parseSuccess(rec[sk]) : null);
    if (!user || user === "-" || Number.isNaN(time) || success === null) {
      skipped++;
      return;
    }
    events.push(makeEvent(n + 1, prefix, user, time, location === "-" ? "" : location, success));
  });
  return { events, skipped, windows };
}

const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const SSH_RE = /(Accepted|Failed) (?:password|publickey|keyboard-interactive(?:\/pam)?|none) for (?:invalid user )?(\S+) from (\S+)/;
const SSH_INVALID_RE = /Invalid user (\S+) from (\S+)/;

/** Parses sshd lines from auth.log / secure / journalctl output (classic or ISO-8601 syslog timestamps). */
function parseAuthLog(text: string, prefix: string, referenceYear: number): ParsedLog | null {
  const events: LoginEvent[] = [];
  let skipped = 0;
  const lines = text.split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n]!;
    const ssh = SSH_RE.exec(line);
    const invalid = ssh ? null : SSH_INVALID_RE.exec(line);
    if (!ssh && !invalid) continue;
    if (events.length >= MAX_EVENTS) {
      skipped++;
      continue;
    }
    let time = NaN;
    const iso = /^(\d{4}-\d\d-\d\dT\S+)/.exec(line);
    const classic = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)/.exec(line);
    if (iso) time = Date.parse(iso[1]!);
    else if (classic) {
      const month = MONTHS[classic[1]!.toLowerCase()];
      if (month !== undefined) time = Date.UTC(referenceYear, month, Number(classic[2]), Number(classic[3]), Number(classic[4]), Number(classic[5]));
    }
    if (Number.isNaN(time)) {
      skipped++;
      continue;
    }
    if (ssh) events.push(makeEvent(n + 1, prefix, ssh[2]!, time, ssh[3]!, ssh[1] === "Accepted"));
    else events.push(makeEvent(n + 1, prefix, invalid![1]!, time, invalid![2]!, false));
  }
  return events.length || skipped ? { format: "auth-log", events, skipped } : null;
}

function tryJson(text: string): Record<string, unknown>[] | null {
  let records: unknown[] | null = null;
  try {
    const parsed = JSON.parse(text) as unknown;
    if (Array.isArray(parsed)) records = parsed;
    else if (parsed && typeof parsed === "object") records = Object.values(parsed).find(Array.isArray) ?? [parsed];
  } catch {
    const lines = text.split(/\r?\n/).filter((l) => l.trim());
    const parsedLines: unknown[] = [];
    for (const l of lines) {
      try { parsedLines.push(JSON.parse(l)); } catch { /* not a JSON line */ }
    }
    if (parsedLines.length && parsedLines.length >= lines.length / 2) records = parsedLines;
  }
  return records?.filter((r): r is Record<string, unknown> => !!r && typeof r === "object" && !Array.isArray(r)) ?? null;
}

/**
 * Detects the log format and extracts login events. Returns null when the file
 * does not look like a login log (content scanning still applies to it).
 */
export function parseLoginLog(text: string, fileName: string, referenceYear = new Date().getUTCFullYear()): ParsedLog | null {
  const prefix = fileName.replace(/[^a-z0-9]+/gi, "_").slice(0, 40) || "file";
  const trimmed = text.trimStart();

  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    const records = tryJson(trimmed);
    if (records) {
      const { events, skipped } = recordsToEvents(records, prefix);
      if (events.length) return { format: "json", events, skipped };
    }
  }

  const auth = parseAuthLog(text, prefix, referenceYear);
  if (auth?.events.length) return auth;

  const firstLine = trimmed.split(/\r?\n/, 1)[0] ?? "";
  if (firstLine.includes(",")) {
    const rows = parseCsvRows(trimmed);
    if (rows.length >= 2) {
      const header = rows[0]!;
      // Event Viewer exports leave the message column without a header, so keep extra cells too.
      const records = rows.slice(1).map((cells) =>
        Object.fromEntries(cells.map((c, i) => [header[i] || `column_${i + 1}`, c])),
      );
      const { events, skipped, windows } = recordsToEvents(records, prefix);
      if (events.length) return { format: windows ? "windows-security" : "login-csv", events, skipped };
    }
  }
  return null;
}
