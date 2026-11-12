export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: "secret" | "malware" | "attack" | "file-type" | "login";
  description: string;
  /** Total matches for this rule in the file. */
  count: number;
  /** A few example locations, with secrets redacted. */
  samples: { line?: number; text: string }[];
}

interface TextRule {
  id: string;
  title: string;
  severity: Severity;
  category: Finding["category"];
  description: string;
  pattern: RegExp;
  redact?: boolean;
}

const MAX_SAMPLES = 5;
export const MAX_SCAN_BYTES = 20 * 1024 * 1024;

const TEXT_RULES: TextRule[] = [
  // Secrets / credentials
  { id: "private-key", title: "Private key", severity: "critical", category: "secret", redact: true, description: "A private key is embedded in the file. Anyone with this file can impersonate the key owner.", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g },
  { id: "aws-key", title: "AWS access key", severity: "high", category: "secret", redact: true, description: "Looks like an AWS access key ID.", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "github-token", title: "GitHub token", severity: "high", category: "secret", redact: true, description: "Looks like a GitHub personal access or app token.", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/g },
  { id: "slack-token", title: "Slack token", severity: "high", category: "secret", redact: true, description: "Looks like a Slack API token.", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { id: "stripe-key", title: "Stripe live secret key", severity: "high", category: "secret", redact: true, description: "Looks like a Stripe live secret key.", pattern: /\b[rs]k_live_[0-9a-zA-Z]{20,}/g },
  { id: "google-api-key", title: "Google API key", severity: "medium", category: "secret", redact: true, description: "Looks like a Google API key.", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "jwt", title: "JSON Web Token", severity: "medium", category: "secret", redact: true, description: "A bearer token (JWT) that may grant access until it expires.", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { id: "credential-url", title: "Credentials in URL", severity: "medium", category: "secret", redact: true, description: "A connection string or URL with an embedded username and password.", pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@"']+:[^\s@/"']{3,}@[^\s"']+/gi },
  { id: "password-assignment", title: "Hard-coded password or secret", severity: "medium", category: "secret", redact: true, description: "A password, secret, or API key assigned to a literal value.", pattern: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?(?!\$\{|<|\*{3}|changeme|null|none|true|false)[^\x00\s"',;]{6,}/gi },

  // Malware / attacker tooling
  { id: "eicar", title: "EICAR antivirus test file", severity: "critical", category: "malware", description: "The industry-standard antivirus test signature. Harmless, but every scanner treats it as malware.", pattern: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/g },
  { id: "mimikatz", title: "Credential dumping tool (Mimikatz)", severity: "critical", category: "malware", description: "References Mimikatz modules used to steal Windows passwords and hashes.", pattern: /\bmimikatz\b|\bsekurlsa::\w+|\blsadump::\w+/gi },
  { id: "reverse-shell", title: "Reverse shell", severity: "critical", category: "malware", description: "A command that hands a remote attacker an interactive shell.", pattern: /\/dev\/tcp\/\d{1,3}(?:\.\d{1,3}){3}\/\d+|\bnc(?:at)?(?:\.exe)?\b[^\n]{0,80}\s-[ec]\s+(?:\/bin\/(?:ba)?sh|cmd(?:\.exe)?)|socket\.socket\([^\n]{0,200}\bdup2\b/gi },
  { id: "webshell", title: "Web shell", severity: "critical", category: "malware", description: "Server-side code that runs commands taken straight from a web request.", pattern: /\b(?:eval|assert|system|exec|passthru|shell_exec|popen)\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/gi },
  { id: "ransomware-shadow", title: "Shadow copy deletion", severity: "critical", category: "malware", description: "Deleting Volume Shadow Copies is a hallmark of ransomware preparing to encrypt files.", pattern: /\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b|\bbcdedit(?:\.exe)?\s+\/set\s+\S*\s*recoveryenabled\s+no\b/gi },
  { id: "ps-encoded", title: "Encoded PowerShell command", severity: "high", category: "malware", description: "PowerShell launched with a Base64-encoded command, commonly used to hide malicious scripts.", pattern: /\bpowershell(?:\.exe)?\b[^\n]{0,120}\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/gi },
  { id: "ps-download-cradle", title: "PowerShell download-and-run", severity: "high", category: "malware", description: "Downloads code from the internet and executes it in memory.", pattern: /\b(?:IEX|Invoke-Expression)\b[^\n]{0,200}\b(?:DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b|\b(?:DownloadString|Invoke-WebRequest|iwr|irm)\b[^\n]{0,200}\|\s*(?:IEX|Invoke-Expression)\b/gi },
  { id: "lolbin", title: "Living-off-the-land binary abuse", severity: "high", category: "malware", description: "A built-in Windows tool used in a way attackers rely on to download or run payloads.", pattern: /\bcertutil(?:\.exe)?\s[^\n]{0,80}-urlcache\b[^\n]{0,80}\s-f\b|\bregsvr32(?:\.exe)?\s[^\n]{0,80}\/i:\s*https?:|\bmshta(?:\.exe)?\s+["']?(?:https?:|vbscript:|javascript:)|\bbitsadmin(?:\.exe)?\s[^\n]{0,80}\/transfer\b|\brundll32(?:\.exe)?\s[^\n]{0,80}javascript:/gi },
  { id: "defense-evasion", title: "Security tooling disabled or logs cleared", severity: "high", category: "malware", description: "Disables Microsoft Defender or wipes event logs to cover tracks.", pattern: /\bSet-MpPreference\b[^\n]{0,80}-Disable(?:RealtimeMonitoring|IOAVProtection|BehaviorMonitoring)\b|\bwevtutil(?:\.exe)?\s+cl\b|\bClear-EventLog\b/gi },
  { id: "js-obfuscated-eval", title: "Obfuscated JavaScript execution", severity: "high", category: "malware", description: "Decodes hidden text and immediately executes it.", pattern: /\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(|\bdocument\.write\s*\(\s*unescape\s*\(/gi },
  { id: "py-exec-encoded", title: "Python executes encoded payload", severity: "high", category: "malware", description: "Decodes Base64/zlib data and executes it.", pattern: /\bexec\s*\(\s*(?:base64\.b64decode|zlib\.decompress|marshal\.loads|__import__\(\s*["'](?:base64|zlib|marshal)["']\))/g },
  { id: "pipe-to-shell", title: "Download piped into a shell", severity: "medium", category: "malware", description: "Runs a remote script without inspecting it first.", pattern: /\b(?:curl|wget)\s[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/g },
  { id: "vba-shell", title: "Office macro spawns programs", severity: "medium", category: "malware", description: "Macro code that creates a shell object or auto-runs when the document opens.", pattern: /CreateObject\(\s*["'](?:WScript\.Shell|Shell\.Application|MSXML2\.XMLHTTP)["']\s*\)|\b(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open)\b/gi },

  // Attack payloads (typically found in web/app logs)
  { id: "log4shell", title: "Log4Shell exploit attempt", severity: "critical", category: "attack", description: "A JNDI lookup string used to exploit CVE-2021-44228.", pattern: /\$\{(?:jndi|\$\{(?:lower|upper|::-j)[^}]*\})[^}]{0,40}:(?:ldaps?|rmi|dns|iiop|nis|corba)?/gi },
  { id: "sql-injection", title: "SQL injection attempt", severity: "medium", category: "attack", description: "Input that tries to alter a database query.", pattern: /\bunion(?:\s|\+|%20|\/\*\*\/)+(?:all(?:\s|\+|%20)+)?select\b|'\s*or\s+'?1'?\s*=\s*'?1|;\s*drop\s+table\b|\bsleep\(\s*\d+\s*\)\s*--|\bxp_cmdshell\b/gi },
  { id: "path-traversal", title: "Path traversal attempt", severity: "medium", category: "attack", description: "Tries to escape a web root to read system files.", pattern: /(?:\.\.[/\\]){2,}|(?:%2e%2e(?:%2f|%5c|\/)){2,}|\/etc\/passwd\b|\bwin\.ini\b/gi },
  { id: "xss", title: "Cross-site scripting attempt", severity: "medium", category: "attack", description: "Script injection aimed at a browser.", pattern: /<script\b[^>]*>[^<]{0,200}(?:document\.cookie|alert\(|fetch\()|\bjavascript:\s*alert\(|\bon(?:error|load)\s*=\s*["']?alert\(/gi },

  { id: "large-encoded-blob", title: "Large encoded blob", severity: "low", category: "malware", description: "A long Base64 string. Often benign (images, certificates) but also used to hide payloads.", pattern: /[A-Za-z0-9+/]{600,}={0,2}/g },
];

const EXECUTABLE_EXT = /\.(?:exe|dll|scr|com|pif|sys|cpl|msi|msp|elf|so|dylib|bin|out|app)$/i;
const RISKY_EXT = /\.(?:exe|scr|com|pif|cpl|msi|hta|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|bat|cmd|lnk|iso|img|jar|reg|docm|xlsm|pptm|dotm)$/i;
const DOUBLE_EXT = /\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|csv|zip|mp[34])\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|ps1|hta|lnk|wsf|jar)$/i;

function redact(value: string): string {
  if (value.length <= 8) return "•".repeat(value.length);
  return `${value.slice(0, 4)}${"•".repeat(Math.min(12, value.length - 6))}${value.slice(-2)}`;
}

function startsWith(bytes: Uint8Array, sig: number[]): boolean {
  return sig.every((b, i) => bytes[i] === b);
}

export function detectFileKind(bytes: Uint8Array): string | null {
  if (startsWith(bytes, [0x4d, 0x5a])) return "Windows executable (PE)";
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return "Linux executable (ELF)";
  if (startsWith(bytes, [0xcf, 0xfa, 0xed, 0xfe]) || startsWith(bytes, [0xce, 0xfa, 0xed, 0xfe])) return "macOS executable (Mach-O)";
  if (startsWith(bytes, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return "Windows shortcut (LNK)";
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) return "ZIP archive / Office document";
  if (startsWith(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return "Legacy Office document (OLE)";
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46])) return "PDF document";
  return null;
}

/** Decodes bytes as text, honouring UTF-16 BOMs (common in Windows exports). */
export function decodeText(bytes: Uint8Array): { text: string; binary: boolean } {
  if (startsWith(bytes, [0xff, 0xfe])) return { text: new TextDecoder("utf-16le").decode(bytes.subarray(2)), binary: false };
  if (startsWith(bytes, [0xfe, 0xff])) return { text: new TextDecoder("utf-16be").decode(bytes.subarray(2)), binary: false };
  const head = bytes.subarray(0, 8192);
  let nulls = 0;
  for (const b of head) if (b === 0) nulls++;
  const binary = nulls > head.length * 0.01;
  // latin1 keeps every byte so signatures inside binaries still match.
  return { text: new TextDecoder(binary ? "latin1" : "utf-8").decode(bytes), binary };
}

function lineAt(lineStarts: number[], index: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

export function scanText(text: string, binary = false): Finding[] {
  const findings: Finding[] = [];
  const lineStarts = [0];
  if (!binary) for (let i = 0; i < text.length; i++) if (text[i] === "\n") lineStarts.push(i + 1);
  for (const rule of TEXT_RULES) {
    if (binary && rule.id === "large-encoded-blob") continue;
    const re = new RegExp(rule.pattern.source, rule.pattern.flags);
    let count = 0;
    const samples: Finding["samples"] = [];
    for (const m of text.matchAll(re)) {
      count++;
      if (samples.length < MAX_SAMPLES) {
        const raw = m[0].replace(/\s+/g, " ").slice(0, 160);
        const shown = rule.redact ? (rule.id === "private-key" ? raw : raw.replace(/([:=]\s*["']?|^)(\S+)$/, (_, p: string, v: string) => p + redact(v))) : raw;
        samples.push({ line: binary ? undefined : lineAt(lineStarts, m.index ?? 0), text: shown });
      }
    }
    if (count) findings.push({ ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, description: rule.description, count, samples });
  }
  return findings;
}

/** Inspects a file's name, type signature, and contents for dangerous material. */
export function scanContent(name: string, bytes: Uint8Array): { findings: Finding[]; text: string | null; kind: string | null; truncated: boolean } {
  const findings: Finding[] = [];
  const kind = detectFileKind(bytes);
  const add = (f: Omit<Finding, "count" | "samples"> & { sample?: string }) =>
    findings.push({ ...f, count: 1, samples: f.sample ? [{ text: f.sample }] : [] });

  if (DOUBLE_EXT.test(name)) {
    add({ ruleId: "double-extension", title: "Disguised file extension", severity: "high", category: "file-type", description: "The name pretends to be a document but actually ends in an executable or script extension.", sample: name });
  } else if (RISKY_EXT.test(name)) {
    add({ ruleId: "risky-extension", title: "Executable or script file", severity: "medium", category: "file-type", description: "This file type can run code when opened. Only open it if you trust the source.", sample: name });
  }
  if (kind && /executable|shortcut/i.test(kind) && !EXECUTABLE_EXT.test(name) && !/\.lnk$/i.test(name)) {
    add({ ruleId: "extension-mismatch", title: "Hidden executable", severity: "high", category: "file-type", description: `The content is a ${kind}, but the file name does not say so.`, sample: `${name} → ${kind}` });
  }

  const truncated = bytes.length > MAX_SCAN_BYTES;
  const { text, binary } = decodeText(truncated ? bytes.subarray(0, MAX_SCAN_BYTES) : bytes);
  if (kind === "ZIP archive / Office document" && /vbaProject\.bin/.test(text)) {
    add({ ruleId: "office-macro", title: "Office document with macros", severity: "medium", category: "malware", description: "The document contains a VBA macro project, a common malware delivery method." });
  }
  if (kind === "Legacy Office document (OLE)" && /_VBA_PROJECT|\bVBA\b/.test(text)) {
    add({ ruleId: "office-macro", title: "Office document with macros", severity: "medium", category: "malware", description: "The document contains a VBA macro project, a common malware delivery method." });
  }
  if (kind === "PDF document" && /\/(?:JavaScript|JS|OpenAction|Launch|EmbeddedFile)\b/.test(text)) {
    add({ ruleId: "pdf-active-content", title: "PDF with active content", severity: "medium", category: "malware", description: "The PDF contains JavaScript, auto-open actions, launch actions, or embedded files." });
  }
  findings.push(...scanText(text, binary));
  return { findings, text: binary ? null : text, kind, truncated };
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
export const severityRank = (s: Severity) => SEVERITY_ORDER.indexOf(s);
