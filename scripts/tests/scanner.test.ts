import { strict as assert } from "node:assert";
import { test } from "node:test";
import { scanFile, scanUploads } from "../../artifacts/login-pattern-radar/src/lib/scanner/index";
import { MAX_SCAN_BYTES, scanContent } from "../../artifacts/login-pattern-radar/src/lib/scanner/content-scan";
import { parseLoginLog } from "../../artifacts/login-pattern-radar/src/lib/scanner/log-parsers";
import { analyze } from "../../artifacts/login-pattern-radar/src/lib/anomaly/pipeline";

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
