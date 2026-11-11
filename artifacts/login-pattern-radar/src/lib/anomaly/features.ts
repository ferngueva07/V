import type { FeatureRow, LoginEvent } from "./types";

export const DAY_MS = 86_400_000;
const MINUTE_MS = 60_000;

/** Feature 1 — hour of day (0-23) on the user's own clock (UTC when no offset is known). */
export function hourOfDay(timestamp: string | number, tzOffsetMin = 0): number {
  return new Date(new Date(timestamp).getTime() - tzOffsetMin * MINUTE_MS).getUTCHours();
}

export function normalizeLocation(location: string): string {
  return location.trim().toLowerCase();
}

function lowerBound(sorted: number[], value: number): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((sorted[mid] ?? 0) < value) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function upperBound(sorted: number[], value: number): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((sorted[mid] ?? 0) <= value) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Number of values in a sorted array that fall within [from, to]. */
export function countInWindow(sortedTimes: number[], from: number, to: number): number {
  return upperBound(sortedTimes, to) - lowerBound(sortedTimes, from);
}

/**
 * Turns raw login attempts into one feature row per successful login.
 *  - F1 hourOfDay: hour of the login on the user's own clock.
 *  - F2 daysSinceLastLogin: days since the same user's previous successful login.
 *  - F3 locationChangeFlag: 1 if the user has never logged in successfully from this location.
 *  - F4 failedAttemptCount: same-user failed attempts within ±windowMinutes of the login.
 */
export function computeFeatures(events: LoginEvent[], windowMinutes = 30): FeatureRow[] {
  const windowMs = windowMinutes * MINUTE_MS;
  const byUser = new Map<string, LoginEvent[]>();
  for (const e of events) {
    const list = byUser.get(e.userId);
    if (list) list.push(e);
    else byUser.set(e.userId, [e]);
  }

  const rows: FeatureRow[] = [];
  for (const [userId, list] of byUser) {
    const sorted = [...list].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    const failTimes = sorted.filter((e) => !e.success).map((e) => Date.parse(e.timestamp));
    let lastSuccess: number | null = null;
    const seen = new Set<string>();

    for (const e of sorted) {
      if (!e.success) continue;
      const t = Date.parse(e.timestamp);
      const loc = normalizeLocation(e.location);
      const days =
        lastSuccess === null ? null : Math.round(((t - lastSuccess) / DAY_MS) * 100) / 100;
      const flag: 0 | 1 = seen.size > 0 && !seen.has(loc) ? 1 : 0;

      rows.push({
        eventId: e.id,
        userId,
        timestamp: e.timestamp,
        location: e.location,
        label: e.label,
        tzOffsetMin: e.tzOffsetMin ?? 0,
        hourOfDay: hourOfDay(t, e.tzOffsetMin ?? 0),
        daysSinceLastLogin: days,
        locationChangeFlag: flag,
        failedAttemptCount: countInWindow(failTimes, t - windowMs, t + windowMs),
      });

      lastSuccess = t;
      seen.add(loc);
    }
  }

  return rows.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
}
