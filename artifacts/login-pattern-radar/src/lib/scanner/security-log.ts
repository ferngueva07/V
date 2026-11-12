import type { Finding, Severity } from "./content-scan";
import { field, readLogRecords, type LogRecord } from "./log-records";

type Rule = { id: string; title: string; severity: Severity; description: string };
const RULES = {
  recon: { id: "sensitive-path-probe", title: "Sensitive file / admin endpoint probing", severity: "high", description: "Requests or access errors reference configuration files, credentials, or exposed administration tools. A probe does not prove access succeeded." },
  tool: { id: "attack-tool-agent", title: "Offensive scanner user agent", severity: "medium", description: "The request identifies a known offensive scanning tool. This may be an authorized security test." },
  sql: { id: "log-sql-attack", title: "SQL injection or sensitive database operation", severity: "high", description: "A request or query contains injection syntax, reads credential tables, or drops audit data. Review authorization and the recorded response." },
  injection: { id: "log-prompt-injection", title: "Instructions embedded in log data", severity: "medium", description: "A log field attempts to instruct an automated analyzer to hide findings. These strings are treated only as data and do not control this scanner." },
  admin: { id: "cloud-privilege-change", title: "Privileged cloud / SaaS permission change", severity: "high", description: "An audit event requests powerful permissions or an administrator role. Confirm the actor, scope, outcome, and approved change record." },
  controls: { id: "security-control-change", title: "Security control disabled or deleted", severity: "high", description: "An audit record reports removal of MFA, logging, encryption, or a security policy. This is a review lead, not proof of unauthorized change." },
  risk: { id: "risky-signin", title: "Identity provider reports a risky sign-in", severity: "high", description: "The identity provider recorded medium/high sign-in risk or a suspicious-login event." },
  legacy: { id: "legacy-auth-no-mfa", title: "Successful legacy authentication without MFA", severity: "high", description: "A successful sign-in uses a legacy authentication client without recorded MFA. Verify whether the account should permit this flow." },
  access: { id: "conditional-access-bypass", title: "Successful sign-in with failed access policy", severity: "high", description: "The sign-in succeeded even though a conditional-access policy recorded failure. Verify policy enforcement and the authentication flow." },
  travel: { id: "impossible-travel", title: "Geographically implausible sign-in travel", severity: "high", description: "Consecutive successful sign-ins for one user are over 500 km apart and imply travel above 900 km/h within 24 hours. VPNs, proxies, and inaccurate IP geolocation can cause false positives." },
  mfa: { id: "mfa-fraud-bypass", title: "MFA fraud, anomalous push, or bypass", severity: "high", description: "The identity provider reports a fraudulent/anomalous push or a successful bypass-code authentication." },
  secrets: { id: "k8s-secret-access", title: "Kubernetes secret access / container execution", severity: "high", description: "The audit record requests secrets or executes commands in a pod. Verify the service account and authorization; routine automation can also do this." },
  mail: { id: "mail-forwarding-rule", title: "Mailbox forwarding or message-hiding rule", severity: "high", description: "An Exchange audit event changes forwarding or creates a rule that forwards/deletes messages. Check destinations and approval for possible mailbox compromise." },
  alert: { id: "security-product-alert", title: "Security product reports a threat", severity: "high", description: "An IDS, WAF, EDR, firewall, or cloud security product recorded a threat finding. A blocked or mitigated alert is not proof of a successful attack." },
  vulnerability: { id: "active-high-vulnerability", title: "Active high / critical vulnerability", severity: "high", description: "The vulnerability scanner reports an active HIGH or CRITICAL package vulnerability. This indicates exposure, not evidence that exploitation occurred." },
  lsass: { id: "lsass-access", title: "Process injection or high-access handle to LSASS", severity: "critical", description: "Sysmon reports a remote thread or a high-access process handle targeting LSASS, a credential theft technique. Validate the source process." },
  roasting: { id: "kerberos-roasting", title: "RC4 Kerberos ticket / missing pre-authentication", severity: "high", description: "A successful Kerberos event uses RC4 for a service ticket or issues an RC4 TGT without pre-authentication. These enable offline password guessing, but legacy configurations can also cause them." },
  anonymous: { id: "s3-anonymous-read", title: "Anonymous S3 object download", severity: "high", description: "S3 recorded a successful object read without an authenticated requester. Confirm that the bucket and object are intended to be public." },
  scrape: { id: "rapid-api-enumeration", title: "Rapid automated API enumeration", severity: "medium", description: "One source using a scripting client requested at least 10 distinct API URLs in a minute. Legitimate integrations may do this too." },
  aliases: { id: "mailbox-alias-burst", title: "Burst of signups sharing one mailbox", severity: "medium", description: "At least 10 distinct plus-addressed email aliases for one mailbox appear within 10 minutes, consistent with automated account farming." },
  scan: { id: "network-port-scan", title: "Rapid multi-port connection attempts", severity: "high", description: "One source contacted at least 5 destination ports within 10 minutes. This can indicate a port scan; check whether it was authorized." },
  denied: { id: "repeated-network-denials", title: "Repeated firewall-denied connections", severity: "medium", description: "A firewall denied at least 5 connections from one source within 10 minutes. This indicates repeated blocked attempts, not a confirmed intrusion." },
  failures: { id: "repeated-auth-failures", title: "Repeated authentication failures", severity: "high", description: "One source has at least 5 authentication failures within 10 minutes. Review the accounts and subsequent successful logins." },
} satisfies Record<string, Rule>;

/** Decode URL escapes for inspection, preserving physical line numbers and malformed escapes. */
function decoded(text: string): string {
  for (let n = 0; n < 2; n++) {
    text = text.replace(/%([0-9a-f]{2})/gi, (original, hex: string) => {
      const code = parseInt(hex, 16);
      return code >= 32 && code < 127 ? String.fromCharCode(code) : original;
    });
  }
  return text;
}

function source(record: LogRecord): string {
  return field(record, "ipaddress", "client.ipaddress", "srcip", "src", "source.ip", "clienthost", "ip_address", "addr")
    || /(?:client[: ]+|from\s+)(\d{1,3}(?:\.\d{1,3}){3})/.exec(record.text)?.[1]
    || /^\s*(\d{1,3}(?:\.\d{1,3}){3})/.exec(record.text)?.[1] || "";
}

function timestamp(record: LogRecord): number {
  const raw = field(record, "timestamp", "time", "createddatetime", "published", "startutc");
  if (/^\d+(?:\.\d+)?$/.test(raw)) return Number(raw) * (Number(raw) < 1e12 ? 1000 : 1);
  if (raw) return Date.parse(raw);
  const iso = /\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?/.exec(record.text)?.[0];
  if (iso) return Date.parse(/[Z+-]\d\d:|Z$/.test(iso) ? iso : `${iso.replace(" ", "T")}Z`);
  const combined = /\[(\d\d)\/([A-Za-z]{3})\/(\d{4}):(\d\d:\d\d:\d\d) ([+-]\d{4})\]/.exec(record.text);
  if (combined) return Date.parse(`${combined[1]} ${combined[2]} ${combined[3]} ${combined[4]} ${combined[5]}`);
  const audit = /\baudit\(([\d.]+):/.exec(record.text);
  return audit ? Number(audit[1]) * 1000 : NaN;
}

interface TimedEvidence { key: string; value: string; time: number; record: LogRecord }

function bursts(rows: TimedEvidence[], minimum: number, windowMs: number, distinct: boolean): TimedEvidence[][] {
  const groups = new Map<string, TimedEvidence[]>();
  for (const row of rows) {
    if (!row.key || !Number.isFinite(row.time)) continue;
    const group = groups.get(row.key) ?? [];
    group.push(row);
    groups.set(row.key, group);
  }
  const found: TimedEvidence[][] = [];
  for (const group of groups.values()) {
    group.sort((a, b) => a.time - b.time);
    let start = 0;
    const counts = new Map<string, number>();
    for (let end = 0; end < group.length; end++) {
      const row = group[end]!;
      counts.set(row.value, (counts.get(row.value) ?? 0) + 1);
      while (row.time - group[start]!.time > windowMs) {
        const key = group[start++]!.value;
        const count = counts.get(key)! - 1;
        if (count) counts.set(key, count); else counts.delete(key);
      }
      if ((distinct ? counts.size : end - start + 1) >= minimum) {
        found.push(group.slice(start, end + 1));
        break;
      }
    }
  }
  return found;
}

export function scanSecurityLog(text: string): Finding[] {
  const findings = new Map<string, Finding>();
  function add(rule: Rule, record: LogRecord, evidence: string) {
    const finding = findings.get(rule.id) ?? { ruleId: rule.id, title: rule.title, severity: rule.severity, category: "attack", description: rule.description, count: 0, samples: [] };
    finding.count++;
    if (finding.samples.length < 5) {
      const context = source(record);
      finding.samples.push({ line: record.line, record: record.record, text: `${context ? `${context} | ` : ""}${evidence}`.slice(0, 360) });
    }
    findings.set(rule.id, finding);
  }
  const api: TimedEvidence[] = [];
  const aliases: TimedEvidence[] = [];
  const ports: TimedEvidence[] = [];
  const failures: TimedEvidence[] = [];
  const denials: TimedEvidence[] = [];
  const travel = new Map<string, { record: LogRecord; time: number; lat: number; lon: number }[]>();
  const records = readLogRecords(text);
  for (const record of records) {
    const inspected = decoded(record.text);
    const match = (rule: Rule, pattern: RegExp) => {
      const found = pattern.exec(inspected);
      if (found) add(rule, record, found[0]);
    };
    match(RULES.recon, /(?:\/|\\)(?:\.env(?:[.\w-]*)|\.git\/config|\.aws\/credentials|(?:admin\/)?web\.config|wp-config\.php|phpmyadmin(?:\/\S*)?)(?=[\s?"',]|$)/i);
    match(RULES.tool, /\b(?:sqlmap|nikto|nmap|nuclei|masscan|gobuster|acunetix)(?:[\/ ][\w.#-]+)?/i);
    match(RULES.sql, /\bunion(?:\s|\+)+(?:all\s+)?select\b|'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+|\b(?:sleep|benchmark)\s*\(|\bselect\b[^\r\n]{0,160}\b(?:pg_shadow|mysql\.user)\b|\bdrop\s+table\s+(?:audit\w*|user_sessions)\b/i);
    match(RULES.injection, /\bignore (?:all |any )?previous instructions\b|\b(?:set|mark|output)[^\r\n]{0,60}(?:severity|severities|analysis)[^\r\n]{0,50}(?:LOW|benign)\b/i);

    const action = field(record, "eventname", "action", "eventtype", "operation", "operationname", "protopayload.methodname");
    const values = Object.values(record.fields).join("\n");
    if (
      (/^(?:CreatePolicy|PutUserPolicy|PutRolePolicy|AttachUserPolicy|AttachRolePolicy)$/.test(action) && /(?:AdministratorAccess|FullAdminAccess|"Action"\s*:\s*"\*")/.test(values))
      || (/roleAssignments\/write$/i.test(action) && /8e3af657-a8ff-443c-a75c-2fe8c4bcb635|b24988ac-6180-42a0-ab88-20f7382dd24c/i.test(values))
      || (/SetIamPolicy$|CreateRole$/.test(action) && /iam\.serviceAccounts\.actAs|resourcemanager\.projects\.setIamPolicy|roles\/(?:owner|editor)/.test(values))
      || /^(?:role_change_to_admin|GRANT_ADMIN_PRIVILEGE)$/.test(action)
      || Object.entries(record.fields).some(([k, v]) => /events\.\d+\.name$/.test(k) && v === "GRANT_ADMIN_PRIVILEGE")
    ) add(RULES.admin, record, `${action || "GRANT_ADMIN_PRIVILEGE"} | ${field(record, "caller", "useridentity.arn", "protopayload.authenticationinfo.principalemail", "actor.user.email", "actor.email")}`);

    if (/^(?:two_factor_authentication\.disabled|admin_totp_disable|TURN_OFF_2_STEP_VERIFICATION|ekm_unenrolled|StopLogging|DeleteTrail|DeleteAccountPasswordPolicy)$/.test(action)
      || (field(record, "configurationitemstatus") === "ResourceDeleted" && /AWS::(?:CloudTrail::Trail|IAM::Policy)/.test(field(record, "resourcetype")))
      || Object.entries(record.fields).some(([k, v]) => /events\.\d+\.name$/.test(k) && v === "TURN_OFF_2_STEP_VERIFICATION")
    ) add(RULES.controls, record, `${action || field(record, "resourcetype")} | ${field(record, "configurationitemstatus", "eventtype", "action")}`);

    const risk = field(record, "risklevelaggregated", "risklevelduringsignin");
    if (/^(?:medium|high)$/i.test(risk) || Object.entries(record.fields).some(([k, v]) => /events\.\d+\.name$/.test(k) && v === "suspicious_login")) {
      add(RULES.risk, record, `risk=${risk || "suspicious_login"} | user=${field(record, "userprincipalname", "actor.email")} | outcome=${field(record, "status.errorcode")}`);
    }
    if (field(record, "status.errorcode") === "0" && /^(?:IMAP4?|POP3?|SMTP|Authenticated SMTP|Other clients|Exchange ActiveSync)$/i.test(field(record, "clientappused"))
      && !field(record, "mfadetail.authmethod")) {
      add(RULES.legacy, record, `${field(record, "userprincipalname")} | client=${field(record, "clientappused")} | errorCode=0 | no MFA detail`);
    }
    if (field(record, "status.errorcode") === "0" && (field(record, "conditionalaccessstatus") === "failure"
      || Object.entries(record.fields).some(([k, v]) => /^appliedconditionalaccesspolicies\.\d+\.result$/.test(k) && v === "failure"))) {
      add(RULES.access, record, `user=${field(record, "userprincipalname")} | errorCode=0 | conditional-access policy=failure`);
    }
    if (/^(?:FRAUD|user_marked_fraud|anomalous_push)$/i.test(field(record, "reason", "result"))
      || (field(record, "factor") === "bypass_code" && field(record, "result") === "SUCCESS")) {
      add(RULES.mfa, record, `user=${field(record, "user.name")} | ${field(record, "result")} | ${field(record, "reason")} | factor=${field(record, "factor")}`);
    }
    if (field(record, "apiversion").startsWith("audit.k8s.io/") && (
      (/^(?:get|list|watch)$/.test(field(record, "verb")) && field(record, "objectref.resource") === "secrets")
      || field(record, "objectref.subresource") === "exec"
    )) add(RULES.secrets, record, `${field(record, "verb")} ${field(record, "requesturi")} | user=${field(record, "user.username")} | response=${field(record, "responsestatus.code")}`);
    if (/^(?:New-InboxRule|Set-InboxRule|Set-Mailbox)$/.test(action) && /ForwardTo|ForwardingSmtpAddress|RedirectTo|DeleteMessage/i.test(values)) {
      add(RULES.mail, record, `${action} | user=${field(record, "userid")} | ${Object.entries(record.fields).filter(([k]) => /parameters\.\d+\.(?:name|value)$/.test(k)).map(([, v]) => v).join(" ")}`);
    }

    const severity = field(record, "severity.label", "severity");
    const inactive = /^(?:RESOLVED|SUPPRESSED|ARCHIVED|CLOSED)$/i.test(field(record, "workflow.status", "recordstate", "status"))
      || field(record, "service.archived") === "true" || field(record, "mitigationstatus", "threatinfo.mitigationstatus") === "marked_as_benign";
    if (!inactive) {
      if (field(record, "type") === "PACKAGE_VULNERABILITY" && field(record, "status") === "ACTIVE" && /^(?:HIGH|CRITICAL)$/.test(severity)) {
        add(RULES.vulnerability, record, `${field(record, "title")} | severity=${severity} | status=ACTIVE`);
      } else if (
        (field(record, "productarn", "detectionsource") && /^(?:HIGH|CRITICAL)$/i.test(severity))
        || (field(record, "arn").includes(":guardduty:") && Number(severity) >= 4)
        || (field(record, "eventtype") === "alert" && Number(field(record, "alert.severity")) > 0 && Number(field(record, "alert.severity")) <= 2)
        || field(record, "threatinfo.confidencelevel") === "malicious"
        || Number(field(record, "rule.level")) >= 7
      ) add(RULES.alert, record, `${field(record, "title", "alert.signature", "threatinfo.threatname", "rule.description")} | severity=${severity || field(record, "alert.severity", "rule.level")}`);
    }
    match(RULES.alert, /%ASA-\d-33800[56]:[^\r\n]+|(?:CEF:\d\|[^\r\n]{0,100}\|THREAT\|[7-9]\||\btype="utm"\s+subtype="(?:ips|virus)"[^\r\n]+)|,\s*THREAT,\s*(?:vulnerability|virus|spyware),[^\r\n]+|\[Priority:\s*[12]\]/i);
    if (field(record, "provider").includes("Sysmon") && /^(?:8|10)$/.test(field(record, "eventid"))
      && /\\lsass\.exe$/i.test(field(record, "targetimage"))
      && (field(record, "eventid") === "8" || /^(?:0x1fffff|0x1f0fff|0x1010|0x1410)$/i.test(field(record, "grantedaccess")))) {
      add(RULES.lsass, record, `${field(record, "sourceimage")} -> ${field(record, "targetimage")} | EventID=${field(record, "eventid")} | access=${field(record, "grantedaccess")}`);
    }
    if (field(record, "provider").includes("Security-Auditing") && field(record, "status") === "0x0"
      && field(record, "ticketencryptiontype").toLowerCase() === "0x17"
      && (field(record, "eventid") === "4769" || (field(record, "eventid") === "4768" && field(record, "preauthtype") === "0"))) {
      add(RULES.roasting, record, `EventID=${field(record, "eventid")} | user=${field(record, "targetusername")} | service=${field(record, "servicename")} | RC4=0x17 | preAuth=${field(record, "preauthtype")}`);
    }
    match(RULES.anonymous, /\b\d{1,3}(?:\.\d{1,3}){3}\s+-\s+\S+\s+REST\.GET\.OBJECT\s+\S+\s+"GET [^"]+"\s+200\b/);

    const time = timestamp(record);
    const src = source(record);
    const lat = field(record, "location.geocoordinates.latitude");
    const lon = field(record, "location.geocoordinates.longitude");
    const user = field(record, "userprincipalname");
    if (user && field(record, "status.errorcode") === "0" && lat && lon && Number.isFinite(time)
      && Number.isFinite(Number(lat)) && Number.isFinite(Number(lon)) && Math.abs(Number(lat)) <= 90 && Math.abs(Number(lon)) <= 180) {
      const history = travel.get(user) ?? [];
      history.push({ record, time, lat: Number(lat), lon: Number(lon) });
      travel.set(user, history);
    }
    const url = field(record, "path", "requestpath") || /"(?:GET|POST|PUT|DELETE) (\S+) HTTP\//.exec(inspected)?.[1] || "";
    if (/^\/api\//.test(url) && /python-requests|Go-http-client|curl\/|axios/i.test(inspected)) api.push({ key: src, value: url, time, record });
    const alias = /^([^,\s+]+)\+([^,@\s]+)@([^,\s]+),[^,]+,[^,]+,([^,]+)/.exec(record.text);
    if (alias) aliases.push({ key: `${alias[1]}@${alias[3]}`.toLowerCase(), value: alias[2]!, time: Date.parse(`${alias[4]!.replace(" ", "T")}Z`), record });

    const failure = /(?:Failed password|authentication fail(?:ed|ure)|password mismatch|user .*? not found|res=failed)/i.test(record.text)
      || (field(record, "status.errorcode") !== "" && field(record, "status.errorcode") !== "0")
      || field(record, "eventid") === "4625" || field(record, "outcome.result") === "FAILURE"
      || (/\b(?:login|auth)/i.test(field(record, "eventtype")) && field(record, "success") === "false")
      || (/\b(?:POST|GET)\b.*\/[^\s"]*(?:login|auth)/i.test(inspected) && /\b(?:401|403)\b/.test(inspected));
    if (failure && (!field(record, "type").startsWith("USER_") || /^(?:USER_AUTH|USER_LOGIN)$/.test(field(record, "type")))) {
      failures.push({ key: src, value: field(record, "userprincipalname", "targetusername", "actor.alternateid", "acct"), time, record });
    }

    const port = field(record, "dpt", "dstport") || /\bDPT=(\d+)/.exec(record.text)?.[1];
    if (src && port) ports.push({ key: src, value: port, time, record });
    const vpc = /^\d\s+\d+\s+eni-\S+\s+(\S+)\s+\S+\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\d{10})\s+/.exec(record.text);
    if (vpc) ports.push({ key: vpc[1]!, value: vpc[2]!, time: Number(vpc[3]) * 1000, record });
    const srx = /RT_FLOW_SESSION_DENY:[^\r\n]*?(\d+(?:\.\d+){3})\/\d+->\S+\/(\d+)/.exec(record.text);
    if (srx) {
      // RFC3164 exports omit the year; use the same reference year for every record.
      const classic = /^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)/.exec(record.text)?.[1];
      const evidence = { key: srx[1]!, value: srx[2]!, time: classic ? Date.parse(`${classic} ${new Date().getUTCFullYear()} UTC`) : NaN, record };
      ports.push(evidence);
      denials.push(evidence);
    }
    for (const [key, tuple] of Object.entries(record.fields)) {
      if (!/flowtuples\.\d+$/.test(key)) continue;
      const cells = tuple.split(",");
      if (cells.length >= 8) ports.push({ key: cells[1]!, value: cells[4]!, time: Number(cells[0]) * 1000, record });
    }
  }
  for (const [rows, minimum, windowMs, distinct, rule] of [
    [api, 10, 60_000, true, RULES.scrape],
    [aliases, 10, 600_000, true, RULES.aliases],
    [ports, 5, 600_000, true, RULES.scan],
    [failures, 5, 600_000, false, RULES.failures],
    [denials, 5, 600_000, false, RULES.denied],
  ] as const) {
    for (const group of bursts(rows, minimum, windowMs, distinct)) {
      const first = group[0]!;
      const last = group[group.length - 1]!;
      add(rule, first.record, `${first.key}: ${distinct ? new Set(group.map((r) => r.value)).size : group.length} ${distinct ? "distinct values" : "events"} between ${new Date(first.time).toISOString()} and ${new Date(last.time).toISOString()} | ${group.slice(0, 5).map((r) => r.value).join(", ")}`);
    }
  }
  for (const [user, history] of travel) {
    history.sort((a, b) => a.time - b.time);
    for (let i = 1; i < history.length; i++) {
      const prev = history[i - 1]!;
      const next = history[i]!;
      const radians = (n: number) => n * Math.PI / 180;
      const a = Math.sin(radians(next.lat - prev.lat) / 2) ** 2
        + Math.cos(radians(prev.lat)) * Math.cos(radians(next.lat)) * Math.sin(radians(next.lon - prev.lon) / 2) ** 2;
      const km = 6371 * 2 * Math.asin(Math.sqrt(Math.min(1, a)));
      const hours = (next.time - prev.time) / 3_600_000;
      if (hours >= 0 && hours <= 24 && km > 500 && (hours === 0 || km / hours > 900)) {
        add(RULES.travel, next.record, `${user}: ${Math.round(km)} km in ${(hours * 60).toFixed(1)} minutes | ${source(prev.record)} at ${new Date(prev.time).toISOString()} -> ${source(next.record)} at ${new Date(next.time).toISOString()}`);
      }
    }
  }
  return [...findings.values()];
}
