/** A single raw login attempt (successful or failed). Timestamps are ISO-8601, interpreted in UTC. */
export interface LoginEvent {
  id: string;
  userId: string;
  timestamp: string;
  location: string;
  success: boolean;
  /** Minutes the user's local clock is behind UTC (JS `getTimezoneOffset`). Absent = UTC. */
  tzOffsetMin?: number | undefined;
  /** Ground-truth tag for injected anomalies in the sample dataset (null for normal events). */
  label: AnomalyLabel | null;
}

export type AnomalyLabel = "odd_hour" | "dormant_return" | "new_location" | "brute_force";

/** The four engineered features, computed for every successful login. */
export interface FeatureRow {
  eventId: string;
  userId: string;
  timestamp: string;
  location: string;
  label: AnomalyLabel | null;
  /** Offset of the user's clock behind UTC in minutes (0 when unknown); used to display the time. */
  tzOffsetMin?: number;
  /** Feature 1: hour of day (0-23, UTC). */
  hourOfDay: number;
  /** Feature 2: days since the user's previous successful login (null on first login). */
  daysSinceLastLogin: number | null;
  /** Feature 3: 1 when the location was never seen before for this user, else 0. */
  locationChangeFlag: 0 | 1;
  /** Feature 4: failed attempts by the same user within ±window minutes of this login. */
  failedAttemptCount: number;
}

export interface FeatureContributions {
  hour: number;
  days: number;
  location: number;
  failed: number;
}

/** Which of the four features look unusual on their own for this login. */
export interface FeatureFlags {
  hour: boolean;
  days: boolean;
  location: boolean;
  failed: boolean;
}

export interface ScoredRow extends FeatureRow {
  score: number;
  isAnomaly: boolean;
  contributions: FeatureContributions;
  reasons: string[];
  flags: FeatureFlags;
}

export interface UserProfile {
  userId: string;
  logins: number;
  knownLocations: string[];
  typicalHour: number;
  lastLogin: string;
}

export interface Bucket {
  bucket: string;
  normal: number;
  flagged: number;
}

export interface AnalysisSummary {
  totalEvents: number;
  successfulLogins: number;
  failedAttempts: number;
  users: number;
  flagged: number;
  threshold: number;
  newLocationLogins: number;
  burstLogins: number;
  injected: { total: number; caught: number };
  byLabel: Partial<Record<AnomalyLabel, { total: number; caught: number }>>;
}

export interface AnalysisResult {
  summary: AnalysisSummary;
  rows: ScoredRow[];
  users: UserProfile[];
  distributions: {
    hours: Bucket[];
    days: Bucket[];
    failed: Bucket[];
    location: Bucket[];
  };
  params: { contamination: number; windowMinutes: number; seed: number };
}

export interface ProbeResult {
  row: ScoredRow;
  threshold: number;
  profile: UserProfile | null;
  scorePercentile: number;
}
