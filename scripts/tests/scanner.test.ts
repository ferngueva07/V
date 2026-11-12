import { strict as assert } from "node:assert";
import { test } from "node:test";
import { loginHeuristics, scanFile, scanUploads } from "../../artifacts/login-pattern-radar/src/lib/scanner/index";
import { MAX_SCAN_BYTES, scanContent } from "../../artifacts/login-pattern-radar/src/lib/scanner/content-scan";
import { parseLoginLog } from "../../artifacts/login-pattern-radar/src/lib/scanner/log-parsers";
import { analyze } from "../../artifacts/login-pattern-radar/src/lib/anomaly/pipeline";
import { scanSecurityLog } from "../../artifacts/login-pattern-radar/src/lib/scanner/security-log";
import { readLogRecords } from "../../artifacts/login-pattern-radar/src/lib/scanner/log-records";

const params = { contamination: 0.08, windowMinutes: 30, seed: 7 };

test("scans arbitrary large files using only the bounded prefix", async () => {
  const file = {
    name: "unknown.ext",
    size: 150 * 1024 * 1024,
    slice(start?: number, end?: number) {
      assert.equal(start, 0);
      assert.equal(end, MAX_SCAN_BYTES);
      return new Blob(["password=examplepassword"]);
    },
  };
  const { report } = await scanFile(file);
  assert.equal(report.error, null);
  assert.equal(report.truncated, true);
  assert.equal(report.sha256, null);
  assert.ok(report.findings.some((f) => f.ruleId === "password-assignment"));
});

test("surfaces read errors instead of claiming files are clean", async () => {
  const { report } = await scanFile({
    name: "broken.bin",
    size: 1,
    slice() { throw new Error("Read denied"); },
  });
  assert.equal(report.error, "Read denied");
});

test("scans binary data with a credential followed by null bytes", () => {
  const bytes = new Uint8Array(1024 * 1024);
  bytes.set(new TextEncoder().encode("password=examplepassword"));
  const result = scanContent("unknown.bin", bytes);
  assert.ok(result.findings.some((f) => f.ruleId === "password-assignment"));
});

test("reports records skipped after the parser limit", () => {
  const row = '{"user":"alice","timestamp":"2026-01-01T00:00:00Z","success":true}';
  const parsed = parseLoginLog(Array.from({ length: 50_001 }, () => row).join("\n"), "log.jsonl");
  assert.equal(parsed?.events.length, 50_000);
  assert.equal(parsed?.skipped, 1);
});

test("does not produce NaN for a dataset with one successful login", () => {
  const events = [{ id: "1", userId: "alice", timestamp: "2026-01-01T00:00:00Z", location: "here", success: true, label: null }];
  assert.throws(() => analyze(events, params), /At least two successful logins/);
});

test("reports analysis failure for a single parsed login", async () => {
  const blob = new Blob(['user_id,timestamp,location,success\nalice,2026-01-01T00:00:00Z,here,true']);
  const file = { name: "log.csv", size: blob.size, slice: blob.slice.bind(blob) };
  const scan = await scanUploads([file], params);
  assert.match(scan.analysisError ?? "", /At least two successful logins/);
  assert.equal(scan.analysis, null);
  assert.equal(scan.flaggedLogins.length, 0);
});

test("parses nested identity outcomes without turning network telemetry into logins", () => {
  const record = { createdDateTime: "2026-01-01T00:00:00Z", userPrincipalName: "person@example.test", ipAddress: "192.0.2.1", status: { errorCode: 0 } };
  const log = parseLoginLog(JSON.stringify({ value: [record, { ...record, status: { errorCode: 50126 } }] }), "renamed.data");
  assert.deepEqual(log?.events.map((e) => [e.userId, e.location, e.success]), [
    ["person@example.test", "192.0.2.1", true], ["person@example.test", "192.0.2.1", false],
  ]);
  assert.equal(parseLoginLog(JSON.stringify({ "@timestamp": record.createdDateTime, event: { category: "network", outcome: "success" }, user: { name: "person" }, source: { ip: "192.0.2.1" } }), "network.json"), null);
});

test("counts only auditd login records, not duplicate USER_ERR messages", () => {
  const log = parseLoginLog([
    'type=USER_LOGIN msg=audit(1705329003.100:1): msg=\'op=login acct="someone" addr=192.0.2.7 res=failed\'',
    'type=USER_ERR msg=audit(1705329003.300:2): msg=\'op=PAM:bad_ident acct="someone" addr=192.0.2.7 res=failed\'',
  ].join("\n"), "audit.data");
  assert.equal(log?.format, "auditd");
  assert.equal(log?.events.length, 1);
  assert.equal(log?.events[0]?.userId, "someone");
  assert.equal(log?.events[0]?.location, "192.0.2.7");
  assert.equal(log?.skipped, 0);
});

test("preserves existing field aliases alongside nested identity records", () => {
  const records = [
    { userPrincipalName: "nested", createdDateTime: "2026-01-01T00:00:00Z", status: { errorCode: 0 }, ipAddress: "192.0.2.1" },
    { email: "legacy", dateandtime: "2026-01-01T00:00:01Z", outcome: "success", country: "elsewhere" },
    { EventID: 4625, TimeCreated: "2026-01-01T00:00:02Z", Message: "Account Name: windows-user\nSource Network Address: 192.0.2.2" },
  ];
  const log = parseLoginLog(JSON.stringify(records), "mixed.json");
  assert.deepEqual(log?.events.map((event) => [event.userId, event.location, event.success]), [
    ["nested", "192.0.2.1", true], ["legacy", "elsewhere", true], ["windows-user", "192.0.2.2", false],
  ]);
  assert.equal(log?.skipped, 0);
});

test("finds sign-in travel from coordinates even without provider risk labels", () => {
  const records = [
    { createdDateTime: "2026-01-01T00:00:00Z", userPrincipalName: "traveler", status: { errorCode: 0 }, location: { geoCoordinates: { latitude: 0, longitude: 0 } } },
    { createdDateTime: "2026-01-01T00:10:00Z", userPrincipalName: "traveler", status: { errorCode: 0 }, location: { geoCoordinates: { latitude: 50, longitude: 50 } } },
  ];
  const finding = scanSecurityLog(JSON.stringify(records)).find((f) => f.ruleId === "impossible-travel");
  assert.equal(finding?.count, 1);
  assert.equal(finding?.samples.length, 1);
  records[1]!.createdDateTime = "2026-01-05T00:00:00Z";
  assert.deepEqual(scanSecurityLog(JSON.stringify(records)), []);
  records[1]!.createdDateTime = "2026-01-01T00:10:00Z";
  records[1]!.status.errorCode = 50126;
  assert.deepEqual(scanSecurityLog(JSON.stringify(records)), []);
});

test("keeps burst detection source-specific, time-bounded, and based on distinct ports", () => {
  const make = (ports: number[], spaced = false, mixed = false) => ports.map((port, i) =>
    `<134>1 2026-01-01T00:${String(spaced ? i * 11 : i).padStart(2, "0")}:00Z fw kernel SRC=192.0.2.${mixed ? i : 1} DST=10.0.0.1 DPT=${port}`).join("\n");
  assert.ok(scanSecurityLog(make([22, 23, 80, 443, 445])).some((f) => f.ruleId === "network-port-scan"));
  assert.deepEqual(scanSecurityLog(make([22, 22, 22, 22, 22])), []);
  assert.deepEqual(scanSecurityLog(make([22, 23, 80, 443, 445], true)), []);
  assert.deepEqual(scanSecurityLog(make([22, 23, 80, 443, 445], false, true)), []);
});

test("does not correlate old login failures or flag a privileged login alone", () => {
  const failed = Array.from({ length: 10 }, (_, i) => ({
    id: `${i}`, userId: `person${i}`, timestamp: `2026-01-01T00:00:${String(i).padStart(2, "0")}Z`,
    location: "192.0.2.1", success: false, label: null,
  }));
  const success = { ...failed[0]!, id: "success", userId: "root", timestamp: "2026-01-01T00:10:09.000Z", success: true };
  assert.ok(loginHeuristics([...failed, success]).some((f) => f.ruleId === "brute-force-success") === false);
  assert.ok(!loginHeuristics([...failed, success]).some((f) => f.ruleId === "privileged-login"));
  assert.deepEqual(loginHeuristics([success]), []);
  success.timestamp = "2026-01-01T00:05:00Z";
  assert.ok(loginHeuristics([...failed, success]).some((f) => f.ruleId === "brute-force-success"));
});

test("decodes escaped payloads and reports the original record rather than a filename label", () => {
  const record = { request: "/?id=1%2520UNION%2520SELECT%25201", client: { ipAddress: "192.0.2.44" } };
  const findings = scanSecurityLog(JSON.stringify({ Records: [record] }, null, 2));
  const sql = findings.find((f) => f.ruleId === "log-sql-attack");
  assert.equal(sql?.samples[0]?.record, 1);
  assert.match(sql?.samples[0]?.text ?? "", /192\.0\.2\.44.*UNION SELECT/i);
});

test("does not promote resolved or low-priority product findings to attacks", () => {
  const findings = [
    { ProductArn: "securityhub", Severity: { Label: "HIGH" }, Title: "Historic alert", Workflow: { Status: "RESOLVED" } },
    { arn: "arn:aws:guardduty:region:account:finding/1", severity: 2, title: "Routine probe" },
    { threatInfo: { confidenceLevel: "malicious", mitigationStatus: "marked_as_benign" } },
    { type: "PACKAGE_VULNERABILITY", severity: "LOW", status: "ACTIVE", title: "Low risk vulnerability" },
  ];
  assert.deepEqual(scanSecurityLog(JSON.stringify(findings)), []);
});

test("retains CSV multiline records and XML evidence locations", () => {
  const csv = readLogRecords('timestamp,user,message\n2026-01-01,person,"line one,\nline two"\n');
  assert.equal(csv.length, 1);
  assert.equal(csv[0]?.fields.message, "line one,\nline two");
  assert.equal(csv[0]?.record, 2);
  const xml = readLogRecords('<Events>\n<Event><System><EventID>4625</EventID></System><EventData><Data Name="TargetUserName">a&amp;b</Data></EventData></Event>\n</Events>');
  assert.equal(xml[0]?.line, 2);
  assert.equal(xml[0]?.fields.targetusername, "a&b");
});
