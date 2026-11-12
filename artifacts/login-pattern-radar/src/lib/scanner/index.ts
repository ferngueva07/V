import { analyze, type ModelParams } from "../anomaly/pipeline";
import type { AnalysisResult, LoginEvent, ScoredRow } from "../anomaly/types";
import { MAX_SCAN_BYTES, scanContent, severityRank, type Finding, type Severity } from "./content-scan";
import { parseLoginLog, type LogFormat } from "./log-parsers";
import { scanSecurityLog } from "./security-log";

export type { Finding, Severity } from "./content-scan";

const BRUTE_FORCE_FAILURES = 10;
const SPRAY_USERS = 5;
const FAILURE_WINDOW_MS = 10 * 60_000;
const IP_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]+)(?::\d+)?$/i;
const PRIVILEGED_USERS = new Set(["root", "admin", "administrator", "sa", "oracle", "postgres"]);

export interface FileReport {
  name: string;
  size: number;
  sha256: string | null;
  kind: string | null;
  logFormat: LogFormat | null;
  loginEvents: number;
  skippedLogRecords: number;
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
  analysisError: string | null;
  totals: Record<Severity, number>;
}

const FORMAT_LABEL: Record<LogFormat, string> = {
  "login-csv": "Login CSV",
  "windows-security": "Windows Security log",
  json: "JSON / JSONL log",
  "auth-log": "Linux auth.log (sshd)",
  auditd: "Linux auditd",
};
export const formatLabel = (f: LogFormat) => FORMAT_LABEL[f];

/** Rule-based login checks that do not depend on the anomaly model. */
export function loginHeuristics(events: LoginEvent[]): Finding[] {
  const findings: Finding[] = [];
  const bySource = new Map<string, {
    failures: number; users: number; sampleUsers: string[]; successAfter: string[];
    recent: { user: string; time: number }[]; start: number; userCounts: Map<string, number>;
  }>();
  const privileged: LoginEvent[] = [];
  const spraySuccess: LoginEvent[] = [];
  for (const e of [...events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))) {
    const key = e.location || "unknown";
    const s = bySource.get(key) ?? { failures: 0, users: 0, sampleUsers: [], successAfter: [], recent: [], start: 0, userCounts: new Map<string, number>() };
    const now = Date.parse(e.timestamp);
    while (s.start < s.recent.length && now - s.recent[s.start]!.time > FAILURE_WINDOW_MS) {
      const user = s.recent[s.start++]!.user;
      const count = s.userCounts.get(user)! - 1;
      if (count) s.userCounts.set(user, count); else s.userCounts.delete(user);
    }
    if (!e.success) {
      s.recent.push({ user: e.userId, time: now });
      s.userCounts.set(e.userId, (s.userCounts.get(e.userId) ?? 0) + 1);
      s.failures = Math.max(s.failures, s.recent.length - s.start);
      if (s.userCounts.size > s.users) {
        s.users = s.userCounts.size;
        s.sampleUsers = [];
        for (const user of s.userCounts.keys()) {
          s.sampleUsers.push(user);
          if (s.sampleUsers.length === 4) break;
        }
      }
    } else {
      const failures = s.recent.length - s.start;
      if (failures >= BRUTE_FORCE_FAILURES && s.successAfter.length < 5) s.successAfter.push(`${e.userId} at ${e.timestamp} (${failures} preceding failures)`);
      if (IP_RE.test(key) && s.userCounts.size >= SPRAY_USERS) spraySuccess.push(e);
      if (IP_RE.test(key) && failures >= 5 && PRIVILEGED_USERS.has(e.userId.toLowerCase())) privileged.push(e);
    }
    bySource.set(key, s);
  }
  // Only IP sources identify a single attacker; city-level locations are shared by many users.
  const ranked = [...bySource.entries()].filter(([k]) => IP_RE.test(k));

  const compromised = ranked.filter(([, s]) => s.successAfter.length);
  if (compromised.length) {
    findings.push({
      ruleId: "brute-force-success", title: "Successful login after brute force", severity: "critical", category: "login",
      description: `A source with ${BRUTE_FORCE_FAILURES}+ failed attempts in the preceding 10 minutes logged in successfully. Investigate possible compromise.`,
      count: compromised.length,
      samples: compromised.slice(0, 5).map(([src, s]) => ({ text: `${src}: ${s.failures} failures, then success as ${s.successAfter[0]}` })),
    });
  }
  const brute = ranked.filter(([, s]) => s.failures >= BRUTE_FORCE_FAILURES).sort((a, b) => b[1].failures - a[1].failures);
  if (brute.length) {
    findings.push({
      ruleId: "brute-force", title: "Brute-force source", severity: "high", category: "login",
      description: `Sources with ${BRUTE_FORCE_FAILURES} or more failed login attempts within 10 minutes.`,
      count: brute.length,
      samples: brute.slice(0, 5).map(([src, s]) => ({ text: `${src}: peak of ${s.failures} failures within 10 minutes; up to ${s.users} account(s) targeted in a window` })),
    });
  }
  const spray = ranked.filter(([, s]) => s.users >= SPRAY_USERS).sort((a, b) => b[1].users - a[1].users);
  if (spray.length) {
    findings.push({
      ruleId: "password-spray", title: "Password spraying / user enumeration", severity: "high", category: "login",
      description: `A single source failed against ${SPRAY_USERS} or more different usernames within 10 minutes.`,
      count: spray.length,
      samples: spray.slice(0, 5).map(([src, s]) => ({ text: `${src}: tried ${s.users} usernames within 10 minutes (${s.sampleUsers.join(", ")}${s.users > 4 ? ", …" : ""})` })),
    });
  }
  if (spraySuccess.length) {
    findings.push({
      ruleId: "password-spray-success", title: "Successful login after password spraying", severity: "critical", category: "login",
      description: `A source that failed against ${SPRAY_USERS}+ usernames within the preceding 10 minutes recorded a successful login. Check MFA and session issuance before concluding compromise.`,
      count: spraySuccess.length,
      samples: spraySuccess.slice(0, 5).map((e) => ({ text: `${e.userId} from ${e.location} at ${e.timestamp}` })),
    });
  }
  if (privileged.length) {
    findings.push({
      ruleId: "privileged-login", title: "Privileged-account login after repeated failures", severity: "high", category: "login",
      description: "A root/administrator-style account logged in from a source with at least 5 failures in the preceding 10 minutes. A privileged login alone is not treated as an attack.",
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

export async function scanFile(file: Pick<File, "name" | "size" | "slice">): Promise<{ report: FileReport; events: LoginEvent[] }> {
  const truncated = file.size > MAX_SCAN_BYTES;
  const base: FileReport = { name: file.name, size: file.size, sha256: null, kind: null, logFormat: null, loginEvents: 0, skippedLogRecords: 0, truncated, error: null, findings: [], worst: null };
  try {
    const bytes = new Uint8Array(await file.slice(0, MAX_SCAN_BYTES).arrayBuffer());
    const hash = truncated ? null : await sha256(bytes);
    const content = scanContent(file.name, bytes);
    const log = content.text ? parseLoginLog(content.text, file.name) : null;
    const events = log?.events ?? [];
    const findings = [...content.findings, ...(content.text ? scanSecurityLog(content.text) : []), ...loginHeuristics(events)].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    return {
      report: { ...base, sha256: hash, kind: content.kind, logFormat: log?.format ?? null, loginEvents: events.length, skippedLogRecords: log?.skipped ?? 0, findings, worst: worstOf(findings) },
      events,
    };
  } catch (err) {
    return { report: { ...base, error: err instanceof Error ? err.message : "The file could not be read." }, events: [] };
  }
}

export async function scanUploads(files: Iterable<Pick<File, "name" | "size" | "slice">>, params: ModelParams): Promise<UploadScanResult> {
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
  let analysisError: string | null = null;
  if (events.some((e) => e.success)) {
    try { analysis = analyze(events, params); } catch (err) {
      analysisError = err instanceof Error ? err.message : "Login analysis could not be completed.";
    }
  }
  const flaggedLogins = (analysis?.rows ?? [])
    .filter((r) => r.isAnomaly)
    .sort((a, b) => b.score - a.score)
    .map((r) => ({ ...r, file: fileOf.get(r.eventId) ?? "" }));

  const totals: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of reports) for (const f of r.findings) totals[f.severity]++;
  return { files: reports, events, flaggedLogins, analysis, analysisError, totals };
}
