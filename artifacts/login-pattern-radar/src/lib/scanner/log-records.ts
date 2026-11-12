/** Splits CSV records, including quoted commas and newlines. */
export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") { row.push(cur.trim()); cur = ""; }
    else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(cur.trim());
      if (row.some(Boolean)) rows.push(row);
      row = [];
      cur = "";
    } else cur += ch;
  }
  row.push(cur.trim());
  if (row.some(Boolean)) rows.push(row);
  return rows;
}

export interface LogRecord {
  fields: Record<string, string>;
  text: string;
  line?: number;
  record?: number;
}

export const keyName = (key: string) => key.toLowerCase().replace(/[^a-z0-9.]/g, "");

export function field(record: LogRecord, ...keys: string[]): string {
  for (const key of keys) {
    const value = record.fields[keyName(key)];
    if (value !== undefined && value !== "") return value;
  }
  return "";
}

function flatten(value: unknown, fields: Record<string, string>, path = "", depth = 0): void {
  if (depth > 20 || value === null || value === undefined) return;
  if (typeof value !== "object") {
    fields[keyName(path)] = String(value);
    // Cloud audit APIs often serialize policy documents and request bodies as JSON strings.
    if (typeof value === "string" && /^\s*[{[]/.test(value)) {
      try { flatten(JSON.parse(value), fields, path, depth + 1); } catch { /* Keep the original string. */ }
    }
    return;
  }
  for (const [key, child] of Object.entries(value)) flatten(child, fields, path ? `${path}.${key}` : key, depth + 1);
}

function structured(value: unknown, record: number): LogRecord {
  const fields: Record<string, string> = Object.create(null);
  flatten(value, fields);
  return { fields, text: Object.entries(fields).map(([k, v]) => `${k}=${v}`).join("\n"), record };
}

const xmlText = (s: string) => s.replace(/&(?:lt|gt|amp|quot|apos);/g, (entity) =>
  ({ "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"', "&apos;": "'" })[entity] ?? entity);

/** Reads exported text, not native binary EVTX. Locations refer to the original upload. */
export function readLogRecords(text: string): LogRecord[] {
  const trimmed = text.trimStart();
  if (/^[{[]/.test(trimmed)) {
    try {
      const value: unknown = JSON.parse(trimmed);
      if (Array.isArray(value)) return value.map((v, i) => structured(v, i + 1));
      if (value && typeof value === "object") {
        const wrappers = ["Records", "records", "value", "items", "entries", "findings", "Findings", "configurationItems"];
        for (const key of wrappers) {
          const records = (value as Record<string, unknown>)[key];
          if (Array.isArray(records)) return records.map((v, i) => structured(v, i + 1));
        }
        return [structured(value, 1)];
      }
    } catch { /* Try JSONL or other text exports below. */ }
  }

  if (/<Event(?:\s|>)/.test(text)) {
    const records: LogRecord[] = [];
    let offset = 0;
    let line = 1;
    for (const match of text.matchAll(/<Event(?:\s[^>]*)?>[\s\S]*?<\/Event>/g)) {
      line += text.slice(offset, match.index).split("\n").length - 1;
      offset = match.index;
      const fields: Record<string, string> = Object.create(null);
      for (const data of match[0].matchAll(/<Data\s+Name=["']([^"']+)["'][^>]*>([\s\S]*?)<\/Data>/g)) {
        fields[keyName(data[1]!)] = xmlText(data[2]!);
      }
      fields.eventid = /<EventID[^>]*>(\d+)<\/EventID>/.exec(match[0])?.[1] ?? "";
      fields.timestamp = /<TimeCreated[^>]*SystemTime=["']([^"']+)/.exec(match[0])?.[1] ?? "";
      fields.provider = /<Provider[^>]*Name=["']([^"']+)/.exec(match[0])?.[1] ?? "";
      records.push({ fields, text: Object.entries(fields).map(([k, v]) => `${k}=${v}`).join("\n"), line });
    }
    return records;
  }

  const lines = text.split(/\r?\n/);
  const first = lines.find((line) => line.trim()) ?? "";
  if (first.includes(",") && !/^[\d[{<]/.test(first) && /timestamp|user|status|ip.address/i.test(first)) {
    const rows = parseCsvRows(text);
    const header = rows.shift() ?? [];
    // A logical CSV record may span several physical lines; report its record number.
    return rows.map((row, i) => {
      const fields = Object.fromEntries(row.map((v, j) => [keyName(header[j] ?? `column${j}`), v]));
      return { fields, text: row.join(" "), record: i + 2 };
    });
  }

  return lines.flatMap((line, i): LogRecord[] => {
    if (!line.trim() || line.startsWith("#")) return [];
    if (line.trimStart().startsWith("{")) {
      try { return [{ ...structured(JSON.parse(line), i + 1), line: i + 1 }]; } catch { /* Retain malformed lines for text checks. */ }
    }
    const fields: Record<string, string> = Object.create(null);
    const auditMessage = /\btype=USER_\w+/.test(line) ? /\bmsg='([^']*)'/.exec(line)?.[1] : undefined;
    for (const input of auditMessage ? [line, auditMessage] : [line]) {
      for (const match of input.matchAll(/\b([\w.]+)=(?:"([^"]*)"|'([^']*)'|([^\s,]+))/g)) {
        fields[keyName(match[1]!)] = match[2] ?? match[3] ?? match[4] ?? "";
      }
    }
    return [{ fields, text: line, line: i + 1 }];
  });
}
