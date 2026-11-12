import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { scanFile } from "../../artifacts/login-pattern-radar/src/lib/scanner/index";

const root = new URL("./fixtures/security-log-samples/", import.meta.url);
interface Sample {
  path: string;
  format: string;
  label: "malicious" | "benign";
  sha256: string;
}
const manifest: Sample[] = JSON.parse(await readFile(new URL("manifest.json", root), "utf8"));

const expectedByFormat: Record<string, string[]> = {
  "aws-alb": ["attack-tool-agent"],
  "apache-error": ["sensitive-path-probe"],
  auditd: ["brute-force-success"],
  "auth-log": ["brute-force", "password-spray"],
  "aws-config": ["security-control-change"],
  "aws-waf": ["log4shell", "log-sql-attack"],
  "azure-activity": ["cloud-privilege-change"],
  "azure-ad-signin": ["risky-signin"],
  carbonblack: ["mimikatz", "ps-encoded"],
  cef: ["security-product-alert", "log-sql-attack"],
  "cisco-asa": ["security-product-alert"],
  cloudflare: ["sensitive-path-probe", "log-sql-attack"],
  cloudtrail: ["cloud-privilege-change"],
  crowdstrike: ["mimikatz"],
  duo: ["mfa-fraud-bypass"],
  ecs: ["mimikatz"],
  "f5-asm": ["log-sql-attack"],
  fortigate: ["security-product-alert"],
  "gcp-audit": ["cloud-privilege-change"],
  "github-audit": ["security-control-change"],
  "google-workspace": ["cloud-privilege-change", "security-control-change"],
  guardduty: ["security-product-alert"],
  haproxy: ["sensitive-path-probe"],
  iis: ["path-traversal"],
  "aws-inspector": ["active-high-vulnerability"],
  jumpcloud: ["security-control-change"],
  "juniper-srx": ["repeated-network-denials"],
  "k8s-audit": ["k8s-secret-access"],
  leef: ["log-sql-attack"],
  m365: ["mail-forwarding-rule"],
  mdatp: ["security-product-alert"],
  mysql: ["log-sql-attack"],
  "nginx-error": ["sensitive-path-probe"],
  "azure-nsg": ["network-port-scan"],
  okta: ["password-spray", "password-spray-success"],
  panos: ["security-product-alert"],
  postgresql: ["log-sql-attack"],
  "aws-s3-access": ["s3-anonymous-read"],
  "aws-securityhub": ["security-product-alert"],
  sentinelone: ["security-product-alert"],
  "slack-audit": ["cloud-privilege-change"],
  snort: ["security-product-alert"],
  suricata: ["security-product-alert"],
  syslog: ["network-port-scan"],
  sysmon: ["lsass-access", "ps-encoded"],
  traefik: ["attack-tool-agent"],
  "vpc-flow": ["network-port-scan"],
  wazuh: ["security-product-alert"],
  zeek: ["log-sql-attack"],
};
const expectedByFile: Record<string, string[]> = {
  "azure_impossible_travel.json": ["impossible-travel", "conditional-access-bypass"],
  "azure_injection_downgrade.json": ["legacy-auth-no-mfa", "log-prompt-injection"],
  "generic_api_scraper.csv": ["rapid-api-enumeration"],
  "generic_signup_mailbox_aliases.csv": ["mailbox-alias-burst"],
  "nginx_credential_stuffing.log": ["repeated-auth-failures"],
  "nginx_prompt_injection.log": ["log-prompt-injection", "repeated-auth-failures"],
  "nginx_recon_sweep.log": ["sensitive-path-probe"],
  "nginx_sqli_exfiltration.log": ["log-sql-attack"],
  "windows_brute_force.xml": ["brute-force", "password-spray"],
  "windows_kerberoasting.xml": ["kerberos-roasting"],
};

for (const sample of manifest) {
  test(`${sample.label}: ${sample.path}`, async () => {
    const data = await readFile(new URL(sample.path, root));
    assert.equal(createHash("sha256").update(data).digest("hex"), sample.sha256, "Fixture differs from upstream");
    const blob = new Blob([data]);
    // Neither the upstream path nor its malicious/benign label reaches the scanner.
    const { report } = await scanFile({ name: "upload.log", size: blob.size, slice: blob.slice.bind(blob) });
    assert.equal(report.error, null);
    assert.equal(report.truncated, false);
    if (sample.label === "malicious") {
      const expected = expectedByFile[sample.path.split("/").pop()!] ?? expectedByFormat[sample.format];
      assert.ok(expected?.length, `Missing test expectations for ${sample.path}`);
      for (const id of expected) assert.ok(report.findings.some((f) => f.ruleId === id), `Missing expected detection: ${id}`);
      for (const finding of report.findings) {
        assert.ok(finding.samples.length > 0, `Missing evidence: ${finding.ruleId}`);
        assert.ok(finding.samples.every((s) => s.text.trim().length > 0), `Empty evidence: ${finding.ruleId}`);
      }
    } else {
      assert.deepEqual(report.findings.map((f) => f.ruleId), [], "Benign sample produced findings");
    }
  });
}
