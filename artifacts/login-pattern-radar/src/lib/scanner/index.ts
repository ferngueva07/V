import { analyze, type ModelParams } from "../anomaly/pipeline";
import type { AnalysisResult, LoginEvent, ScoredRow } from "../anomaly/types";
import { scanContent, severityRank, type Finding, type Severity } from "./content-scan";
import { parseLoginLog, type LogFormat } from "./log-parsers";

export type { Finding, Severity } from "./content-scan";

export const MAX_FILE_BYTES = 100 * 1024 * 1024;
const BRUTE_FORCE_FAILURES = 10;
const SPRAY_USERS = 5;
const IP_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]+)(?::\d+)?$/i;
const PRIVILEGED_USERS = new Set(["root", "admin", "administrator", "sa", "oracle", "postgres"]);

export interface FileReport {
  name: string;
  size: number;
  sha256: string | null;
  kind: string | null;
  logFormat: LogFormat | null;
  loginEvents: number;
  truncated: boolean;
  error: string | null;
  findings: Finding[];
  worst: Severity | null;
}

export interface UploadScanResult {
  files: FileReport[];
  events: LoginEvent[];
  /** Model-flagged logins with the file each came from. */
  flaggedLogins: (ScoredRow & { file: string })[];
  analysis: AnalysisResult | null;
  totals: Record<Severity, number>;
}

const FORMAT_LABEL: Record<LogFormat, string> = {
  "login-csv": "Login CSV",
  "windows-security": "Windows Security log",
  json: "JSON / JSONL log",
  "auth-log": "Linux auth.log (sshd)",
};
export const formatLabel = (f: LogFormat) => FORMAT_LABEL[f];

/** Rule-based login checks that do not depend on the anomaly model. */
export function loginHeuristics(events: LoginEvent[]): Finding[] {
  const findings: Finding[] = [];
  const bySource = new Map<string, { failures: number; users: Set<string>; successAfter: string[] }>();
  for (const e of [...events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))) {
    const key = e.location || "unknown";
    const s = bySource.get(key) ?? { failures: 0, users: new Set<string>(), successAfter: [] };
    if (!e.success) {
      s.failures++;
      s.users.add(e.userId);
    } else if (s.failures >= BRUTE_FORCE_FAILURES) s.successAfter.push(`${e.userId} at ${e.timestamp}`);
    bySource.set(key, s);
  }
  // Only IP sources identify a single attacker; city-level locations are shared by many users.
  const ranked = [...bySource.entries()].filter(([k]) => IP_RE.test(k));

  const compromised = ranked.filter(([, s]) => s.successAfter.length);
  if (compromised.length) {
    findings.push({
      ruleId: "brute-force-success", title: "Successful login after brute force", severity: "critical", category: "login",
      description: `A source with ${BRUTE_FORCE_FAILURES}+ failed attempts later logged in successfully — the account may be compromised.`,
      count: compromised.length,
      samples: compromised.slice(0, 5).map(([src, s]) => ({ text: `${src}: ${s.failures} failures, then success as ${s.successAfter[0]}` })),
    });
  }
  const brute = ranked.filter(([, s]) => s.failures >= BRUTE_FORCE_FAILURES).sort((a, b) => b[1].failures - a[1].failures);
  if (brute.length) {
    findings.push({
      ruleId: "brute-force", title: "Brute-force source", severity: "high", category: "login",
      description: `Sources with ${BRUTE_FORCE_FAILURES} or more failed login attempts.`,
      count: brute.length,
      samples: brute.slice(0, 5).map(([src, s]) => ({ text: `${src}: ${s.failures} failed attempts against ${s.users.size} account(s)` })),
    });
  }
  const spray = ranked.filter(([, s]) => s.users.size >= SPRAY_USERS).sort((a, b) => b[1].users.size - a[1].users.size);
  if (spray.length) {
    findings.push({
      ruleId: "password-spray", title: "Password spraying / user enumeration", severity: "high", category: "login",
      description: `A single source failed against ${SPRAY_USERS} or more different usernames.`,
      count: spray.length,
      samples: spray.slice(0, 5).map(([src, s]) => ({ text: `${src}: tried ${s.users.size} usernames (${[...s.users].slice(0, 4).join(", ")}${s.users.size > 4 ? ", …" : ""})` })),
    });
  }
  const privileged = events.filter((e) => e.success && PRIVILEGED_USERS.has(e.userId.toLowerCase()));
  if (privileged.length) {
    findings.push({
      ruleId: "privileged-login", title: "Direct privileged-account login", severity: "medium", category: "login",
      description: "Successful logins straight into root/administrator-style accounts, which should normally be disabled for remote access.",
      count: privileged.length,
      samples: privileged.slice(0, 5).map((e) => ({ text: `${e.userId} from ${e.location} at ${e.timestamp}` })),
    });
  }
  return findings;
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<string | null> {
  try {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}

const worstOf = (findings: Finding[]): Severity | null =>
  findings.reduce<Severity | null>((w, f) => (w === null || severityRank(f.severity) < severityRank(w) ? f.severity : w), null);

export async function scanFile(file: { name: string; size: number; arrayBuffer(): Promise<ArrayBuffer> }): Promise<{ report: FileReport; events: LoginEvent[] }> {
  const base: FileReport = { name: file.name, size: file.size, sha256: null, kind: null, logFormat: null, loginEvents: 0, truncated: false, error: null, findings: [], worst: null };
  if (file.size > MAX_FILE_BYTES) {
    return { report: { ...base, error: `File is larger than ${MAX_FILE_BYTES / 1024 / 1024} MB and was not scanned.` }, events: [] };
  }
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const [hash, content] = [await sha256(bytes), scanContent(file.name, bytes)];
    const log = content.text ? parseLoginLog(content.text, file.name) : null;
    const events = log?.events ?? [];
    const findings = [...content.findings, ...loginHeuristics(events)].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    return {
      report: { ...base, sha256: hash, kind: content.kind, logFormat: log?.format ?? null, loginEvents: events.length, truncated: content.truncated, findings, worst: worstOf(findings) },
      events,
    };
  } catch (err) {
    return { report: { ...base, error: err instanceof Error ? err.message : "The file could not be read." }, events: [] };
  }
}

export async function scanUploads(files: Iterable<File>, params: ModelParams): Promise<UploadScanResult> {
  const reports: FileReport[] = [];
  const events: LoginEvent[] = [];
  const fileOf = new Map<string, string>();
  for (const file of files) {
    const { report, events: fileEvents } = await scanFile(file);
    reports.push(report);
    for (const e of fileEvents) {
      // Same-named files would otherwise collide on event ids.
      const id = `${reports.length}_${e.id}`;
      fileOf.set(id, file.name);
      events.push({ ...e, id });
    }
  }

  let analysis: AnalysisResult | null = null;
  if (events.some((e) => e.success)) {
    try { analysis = analyze(events, params); } catch { analysis = null; }
  }
  const flaggedLogins = (analysis?.rows ?? [])
    .filter((r) => r.isAnomaly)
    .sort((a, b) => b.score - a.score)
    .map((r) => ({ ...r, file: fileOf.get(r.eventId) ?? "" }));

  const totals: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of reports) for (const f of r.findings) totals[f.severity]++;
  return { files: reports, events, flaggedLogins, analysis, totals };
}
