import { computeFeatures } from "./features";
import { IsolationForest } from "./isolation-forest";
import type {
  AnalysisResult,
  AnomalyLabel,
  Bucket,
  FeatureContributions,
  FeatureFlags,
  FeatureRow,
  LoginEvent,
  ProbeResult,
  ScoredRow,
  UserProfile,
} from "./types";

export interface ModelParams {
  contamination: number;
  windowMinutes: number;
  seed: number;
}

function quantile(values: number[], q: number): number {
  if (values.length === 0) return 1;
  const s = [...values].sort((a, b) => a - b);
  const pos = Math.min(s.length - 1, Math.max(0, Math.ceil(q * s.length) - 1));
  return s[pos]!;
}

function median(values: number[]): number {
  return quantile(values, 0.5);
}

interface PopulationStats {
  hourShare: number[];
  /** Hour-of-day encoded as rarity (-log smoothed share), so 03:00 sits far from 09:00 on one axis. */
  hourRarity: number[];
  daysP95: number;
  baseline: number[];
}

function populationStats(rows: FeatureRow[]): PopulationStats {
  const counts = new Array<number>(24).fill(0);
  for (const r of rows) counts[r.hourOfDay] = (counts[r.hourOfDay] ?? 0) + 1;
  const n = Math.max(1, rows.length);
  const hourShare = counts.map((c) => c / n);
  const hourRarity = counts.map((c) => -Math.log((c + 1) / (n + 24)));
  const modeHour = hourShare.indexOf(Math.max(...hourShare));
  const days = rows.map((r) => r.daysSinceLastLogin ?? 0);
  return {
    hourShare,
    hourRarity,
    daysP95: quantile(days, 0.95),
    baseline: [hourRarity[modeHour] ?? 0, median(days), 0, 0],
  };
}

/** Model input built from the four features (first login counts as 0 days). */
function toVector(row: FeatureRow, stats: PopulationStats): number[] {
  return [
    stats.hourRarity[row.hourOfDay] ?? 0,
    row.daysSinceLastLogin ?? 0,
    row.locationChangeFlag,
    row.failedAttemptCount,
  ];
}

function explain(
  row: FeatureRow,
  stats: PopulationStats,
  windowMinutes: number,
): { reasons: string[]; flags: FeatureFlags } {
  const reasons: string[] = [];
  const share = stats.hourShare[row.hourOfDay] ?? 0;
  const days = row.daysSinceLastLogin;
  const flags: FeatureFlags = {
    hour: share < 0.02,
    days: days !== null && days >= Math.max(7, stats.daysP95),
    location: row.locationChangeFlag === 1,
    failed: row.failedAttemptCount >= 3,
  };
  if (flags.hour) {
    const how =
      share < 0.001
        ? "almost no logins happen then"
        : `only ${(share * 100).toFixed(1)}% of logins`;
    reasons.push(`Unusual hour: ${String(row.hourOfDay).padStart(2, "0")}:00 UTC (${how})`);
  }
  if (flags.days && days !== null) {
    reasons.push(`Returned after ${Math.round(days)} days away`);
  }
  if (flags.location) reasons.push(`First login ever from ${row.location}`);
  if (flags.failed) {
    reasons.push(
      `${row.failedAttemptCount} failed attempts within ±${windowMinutes} min — possible brute force`,
    );
  }
  return { reasons, flags };
}

export interface TrainedModel {
  features: FeatureRow[];
  forest: IsolationForest;
  scores: number[];
  threshold: number;
  stats: PopulationStats;
}

export function train(events: LoginEvent[], params: ModelParams): TrainedModel {
  const features = computeFeatures(events, params.windowMinutes);
  if (features.length === 0) throw new Error("No successful logins to analyze.");
  if (features.length === 1) throw new Error("At least two successful logins are needed to calculate an anomaly score.");
  const stats = populationStats(features);
  const X = features.map((f) => toVector(f, stats));
  const forest = new IsolationForest({ nTrees: 150, sampleSize: 256, seed: params.seed }).fit(X);
  const scores = X.map((x) => forest.score(x));
  return {
    features,
    forest,
    scores,
    threshold: quantile(scores, 1 - params.contamination),
    stats,
  };
}

const round = (n: number, d = 4) => Math.round(n * 10 ** d) / 10 ** d;

/** Ablation: how much the score drops when one feature is reset to a typical value. */
function contributions(
  forest: IsolationForest,
  vec: number[],
  score: number,
  baseline: number[],
): FeatureContributions {
  const ablate = (dims: number[]) => {
    const v = [...vec];
    for (const d of dims) v[d] = baseline[d]!;
    return Math.max(0, score - forest.score(v));
  };
  return {
    hour: round(ablate([0])),
    days: round(ablate([1])),
    location: round(ablate([2])),
    failed: round(ablate([3])),
  };
}

export function scoreRow(
  model: TrainedModel,
  row: FeatureRow,
  windowMinutes: number,
  score?: number,
): ScoredRow {
  const vec = toVector(row, model.stats);
  const s = score ?? model.forest.score(vec);
  return {
    ...row,
    score: round(s),
    isAnomaly: s >= model.threshold,
    contributions: contributions(model.forest, vec, s, model.stats.baseline),
    ...explain(row, model.stats, windowMinutes),
  };
}

export function buildProfiles(rows: FeatureRow[]): UserProfile[] {
  const byUser = new Map<string, FeatureRow[]>();
  for (const r of rows) {
    const l = byUser.get(r.userId);
    if (l) l.push(r);
    else byUser.set(r.userId, [r]);
  }
  return [...byUser.entries()]
    .map(([userId, list]) => ({
      userId,
      logins: list.length,
      knownLocations: [...new Set(list.map((r) => r.location))],
      typicalHour: median(list.map((r) => r.hourOfDay)),
      lastLogin: list[list.length - 1]!.timestamp,
    }))
    .sort((a, b) => a.userId.localeCompare(b.userId));
}

function bucketize(rows: ScoredRow[], labels: string[], keyOf: (r: ScoredRow) => string): Bucket[] {
  const map = new Map(labels.map((b) => [b, { bucket: b, normal: 0, flagged: 0 }]));
  for (const r of rows) {
    const b = map.get(keyOf(r));
    if (!b) continue;
    if (r.isAnomaly) b.flagged++;
    else b.normal++;
  }
  return labels.map((l) => map.get(l)!);
}

const DAY_BUCKETS = ["first", "<1", "1-2", "3-7", "8-14", "15-30", "31-60", "60+"];
function dayBucket(d: number | null): string {
  if (d === null) return "first";
  if (d < 1) return "<1";
  if (d < 3) return "1-2";
  if (d < 8) return "3-7";
  if (d < 15) return "8-14";
  if (d < 31) return "15-30";
  if (d <= 60) return "31-60";
  return "60+";
}
const FAILED_BUCKETS = ["0", "1", "2", "3-5", "6-10", "11+"];
function failedBucket(n: number): string {
  if (n <= 2) return String(n);
  if (n <= 5) return "3-5";
  if (n <= 10) return "6-10";
  return "11+";
}

export function analyze(events: LoginEvent[], params: ModelParams): AnalysisResult {
  const model = train(events, params);
  const rows = model.features.map((f, i) =>
    scoreRow(model, f, params.windowMinutes, model.scores[i]),
  );

  const byLabel: AnalysisResult["summary"]["byLabel"] = {};
  let injectedTotal = 0;
  let injectedCaught = 0;
  for (const r of rows) {
    if (!r.label) continue;
    const entry = (byLabel[r.label as AnomalyLabel] ??= { total: 0, caught: 0 });
    entry.total++;
    injectedTotal++;
    if (r.isAnomaly) {
      entry.caught++;
      injectedCaught++;
    }
  }

  return {
    summary: {
      totalEvents: events.length,
      successfulLogins: rows.length,
      failedAttempts: events.filter((e) => !e.success).length,
      users: new Set(rows.map((r) => r.userId)).size,
      flagged: rows.filter((r) => r.isAnomaly).length,
      threshold: round(model.threshold),
      newLocationLogins: rows.filter((r) => r.locationChangeFlag === 1).length,
      burstLogins: rows.filter((r) => r.failedAttemptCount >= 3).length,
      injected: { total: injectedTotal, caught: injectedCaught },
      byLabel,
    },
    rows,
    users: buildProfiles(model.features),
    distributions: {
      hours: bucketize(
        rows,
        Array.from({ length: 24 }, (_, h) => String(h)),
        (r) => String(r.hourOfDay),
      ),
      days: bucketize(rows, DAY_BUCKETS, (r) => dayBucket(r.daysSinceLastLogin)),
      failed: bucketize(rows, FAILED_BUCKETS, (r) => failedBucket(r.failedAttemptCount)),
      location: bucketize(rows, ["Known location", "New location"], (r) =>
        r.locationChangeFlag ? "New location" : "Known location",
      ),
    },
    params,
  };
}

export interface Probe {
  userId: string;
  timestamp: string;
  location: string;
  failedAttempts: number;
}

/** Scores a hypothetical login against the model trained on `events`, using the user's real history. */
export function scoreProbe(events: LoginEvent[], params: ModelParams, probe: Probe): ProbeResult {
  const model = train(events, params);
  const t = Date.parse(probe.timestamp);
  if (Number.isNaN(t)) throw new Error("Invalid timestamp");
  const windowMs = params.windowMinutes * 60_000;
  const spacing = Math.min(20_000, windowMs / (probe.failedAttempts + 1));
  const userEvents = events.filter((e) => e.userId === probe.userId);
  const extra: LoginEvent[] = [];
  for (let i = 0; i < probe.failedAttempts; i++) {
    extra.push({
      id: `probe_fail_${i}`,
      userId: probe.userId,
      timestamp: new Date(t - (i + 1) * spacing).toISOString(),
      location: probe.location,
      success: false,
      label: null,
    });
  }
  extra.push({
    id: "probe",
    userId: probe.userId,
    timestamp: new Date(t).toISOString(),
    location: probe.location,
    success: true,
    label: null,
  });
  const feat = computeFeatures([...userEvents, ...extra], params.windowMinutes).find(
    (r) => r.eventId === "probe",
  );
  if (!feat) throw new Error("Could not compute features for this login");
  const row = scoreRow(model, feat, params.windowMinutes);
  const below = model.scores.filter((s) => s < row.score).length;
  return {
    row,
    threshold: round(model.threshold),
    profile: buildProfiles(model.features.filter((f) => f.userId === probe.userId))[0] ?? null,
    scorePercentile: round((below / model.scores.length) * 100, 1),
  };
}

export interface UserLoginResult extends ScoredRow {
  /** Successful logins by this user before this one. */
  priorLogins: number;
  /** "learning" while the account has too little history to judge by its own pattern. */
  status: "normal" | "suspicious" | "learning";
}

export const MIN_HISTORY = 3;

function withStatus(row: ScoredRow, priorLogins: number): UserLoginResult {
  const bruteForce = row.flags.failed;
  const status = bruteForce
    ? "suspicious"
    : priorLogins < MIN_HISTORY
      ? "learning"
      : row.isAnomaly
        ? "suspicious"
        : "normal";
  return { ...row, priorLogins, status };
}

/** Scores every successful login in one user's history against an already-trained model. */
export function scoreUserHistory(
  model: TrainedModel,
  userEvents: LoginEvent[],
  windowMinutes: number,
): UserLoginResult[] {
  return computeFeatures(userEvents, windowMinutes).map((f, i) =>
    withStatus(scoreRow(model, f, windowMinutes), i),
  );
}

/** Scores a hypothetical login (with `failedAttempts` just before it) against a user's real history. */
export function scoreHypothetical(
  model: TrainedModel,
  userEvents: LoginEvent[],
  probe: Probe & { tzOffsetMin?: number },
  windowMinutes: number,
): UserLoginResult {
  const t = Date.parse(probe.timestamp);
  if (Number.isNaN(t)) throw new Error("Invalid timestamp");
  const spacing = Math.min(20_000, (windowMinutes * 60_000) / (probe.failedAttempts + 1));
  const extra: LoginEvent[] = [];
  for (let i = 0; i < probe.failedAttempts; i++) {
    extra.push({
      id: `probe_fail_${i}`,
      userId: probe.userId,
      timestamp: new Date(t - (i + 1) * spacing).toISOString(),
      location: probe.location,
      success: false,
      tzOffsetMin: probe.tzOffsetMin,
      label: null,
    });
  }
  extra.push({
    id: "probe",
    userId: probe.userId,
    timestamp: new Date(t).toISOString(),
    location: probe.location,
    success: true,
    tzOffsetMin: probe.tzOffsetMin,
    label: null,
  });
  const rows = scoreUserHistory(model, [...userEvents, ...extra], windowMinutes);
  const hit = rows.find((r) => r.eventId === "probe");
  if (!hit) throw new Error("Could not compute features for this login");
  return hit;
}
