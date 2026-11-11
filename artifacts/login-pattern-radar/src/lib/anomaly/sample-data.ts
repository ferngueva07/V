import { mulberry32 } from "./isolation-forest";
import type { AnomalyLabel, LoginEvent } from "./types";

const HOME_CITIES = [
  "Chicago, US",
  "Austin, US",
  "Denver, US",
  "Toronto, CA",
  "London, UK",
  "Madrid, ES",
  "Mexico City, MX",
  "Berlin, DE",
];
export const FOREIGN_CITIES = [
  "Lagos, NG",
  "Bucharest, RO",
  "Shenzhen, CN",
  "São Paulo, BR",
  "Minsk, BY",
  "Jakarta, ID",
  "Hanoi, VN",
];
export const NAMES = [
  "ana.ruiz", "ben.okafor", "chloe.park", "dev.patel", "elena.rossi", "farid.haddad",
  "grace.kim", "hugo.martin", "isla.nguyen", "jonah.weiss", "kara.singh", "liam.obrien",
  "maya.cohen", "nico.silva", "olivia.berg", "pablo.diaz", "quinn.taylor", "rosa.lopez",
  "sam.ito", "tara.walsh", "uma.reddy", "victor.hale", "wren.adams", "xavier.cruz",
  "yara.nasser", "zoe.fischer", "aiden.moore", "bea.santos",
];

/** Fixed end date keeps the sample deterministic for a given seed. */
export const SAMPLE_END = Date.UTC(2026, 10, 10);
const DAYS = 90;
const DAY_MS = 86_400_000;

export function generateSampleEvents(seed = 7): LoginEvent[] {
  const rng = mulberry32(seed * 7919 + 13);
  const pick = <T,>(arr: readonly T[]): T => arr[Math.floor(rng() * arr.length)]!;
  const gauss = () => {
    const u = 1 - rng();
    const v = rng();
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  };
  const start = SAMPLE_END - DAYS * DAY_MS;
  const raw: Omit<LoginEvent, "id">[] = [];
  const push = (userId: string, t: number, location: string, success: boolean, label: AnomalyLabel | null) =>
    raw.push({ userId, timestamp: new Date(t).toISOString(), location, success, label });

  const profiles = NAMES.map((userId, i) => {
    const r = rng();
    const peak = r < 0.6 ? 7.5 + rng() * 2.5 : r < 0.9 ? 12 + rng() * 4 : 18 + rng() * 3;
    const home = pick(HOME_CITIES);
    let second: string | null = null;
    if (rng() < 0.35) {
      second = pick(HOME_CITIES);
      if (second === home) second = null;
    }
    const dormant = i === 3 || i === 17;
    return {
      userId,
      home,
      second,
      peak,
      sd: 0.7 + rng() * 1.1,
      pDaily: dormant ? 0.97 : 0.55 + rng() * 0.4,
      gap: dormant ? { from: 18, to: 18 + 55 + Math.floor(rng() * 12) } : null,
    };
  });

  for (const p of profiles) {
    let markReturn = false;
    for (let d = 0; d < DAYS; d++) {
      if (p.gap && d >= p.gap.from && d < p.gap.to) {
        markReturn = true;
        continue;
      }
      if (rng() >= p.pDaily) continue;
      const sessions = rng() < 0.2 ? 2 : 1;
      for (let s = 0; s < sessions; s++) {
        const hour = Math.min(22, Math.max(6, Math.round(p.peak + gauss() * p.sd + s * 4)));
        const t = start + d * DAY_MS + hour * 3_600_000 + Math.floor(rng() * 60) * 60_000;
        const loc = p.second && rng() < 0.12 ? p.second : p.home;
        if (rng() < 0.03) {
          const typos = rng() < 0.85 ? 1 : 2;
          for (let k = typos; k >= 1; k--) push(p.userId, t - k * 45_000, loc, false, null);
        }
        push(p.userId, t, loc, true, markReturn ? "dormant_return" : null);
        markReturn = false;
      }
    }
  }

  const randomDayTime = (hour: number) =>
    start + (30 + Math.floor(rng() * (DAYS - 31))) * DAY_MS + hour * 3_600_000 + Math.floor(rng() * 60) * 60_000;

  for (let i = 0; i < 6; i++) {
    const p = pick(profiles);
    push(p.userId, randomDayTime(1 + Math.floor(rng() * 4)), p.home, true, "odd_hour");
  }
  for (let i = 0; i < 5; i++) {
    const p = pick(profiles);
    push(p.userId, randomDayTime(Math.round(p.peak)), pick(FOREIGN_CITIES), true, "new_location");
  }
  for (let i = 0; i < 5; i++) {
    const p = pick(profiles);
    const loc = pick(FOREIGN_CITIES);
    const t = randomDayTime(Math.floor(rng() * 24));
    const attempts = 6 + Math.floor(rng() * 9);
    for (let k = attempts; k >= 1; k--) push(p.userId, t - k * (20_000 + Math.floor(rng() * 40_000)), loc, false, null);
    push(p.userId, t, loc, true, "brute_force");
  }

  return raw
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
    .map((e, i) => ({ ...e, id: `evt_${String(i + 1).padStart(5, "0")}` }));
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function eventsToCsv(events: LoginEvent[]): string {
  const lines = ["user_id,timestamp,location,success"];
  for (const e of events) lines.push([e.userId, e.timestamp, e.location, e.success ? "true" : "false"].map(csvCell).join(","));
  return lines.join("\n");
}
