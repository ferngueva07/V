import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, Route, Switch, useLocation } from 'wouter';
import {
  Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, BadgeCheck, Clock3, FileUp,
  Fingerprint, Gauge, Info, MapPin, Menu, RotateCcw, Search, ShieldAlert, ShieldCheck,
  SlidersHorizontal, Sparkles, X,
} from 'lucide-react';
import { eventsToCsv, generateSampleEvents } from '@/lib/anomaly/sample-data';
import { analyze, scoreProbe } from '@/lib/anomaly/pipeline';
import { parseLoginCsv } from '@/lib/anomaly/csv';
import type { AnalysisResult, LoginEvent, ProbeResult, ScoredRow } from '@/lib/anomaly/types';

type ModelParams = { contamination: number; windowMinutes: number; seed: number };
const SEED = 7;
const DEFAULT_PARAMS: ModelParams = { contamination: 0.08, windowMinutes: 30, seed: SEED };

function readStoredEvents(): LoginEvent[] {
  try {
    const saved = localStorage.getItem('lpr-events-v1');
    return saved ? JSON.parse(saved) as LoginEvent[] : generateSampleEvents(SEED);
  } catch {
    return generateSampleEvents(SEED);
  }
}
function readStoredParams(): ModelParams {
  try {
    const saved = localStorage.getItem('lpr-params-v1');
    return saved ? { ...DEFAULT_PARAMS, ...JSON.parse(saved) as Partial<ModelParams> } : DEFAULT_PARAMS;
  } catch {
    return DEFAULT_PARAMS;
  }
}
function readStoredSource(): string {
  try { return localStorage.getItem('lpr-events-v1') ? 'Imported dataset' : 'Generated sample'; }
  catch { return 'Generated sample'; }
}
const fmt = (timestamp: string) => new Intl.DateTimeFormat('en', {
  month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC',
  timeZoneName: 'short',
}).format(new Date(timestamp));
const shortDate = (timestamp: string) => new Intl.DateTimeFormat('en', {
  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC',
}).format(new Date(timestamp));
const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

function App() {
  const [events, setEvents] = useState<LoginEvent[]>(readStoredEvents);
  const [params, setParams] = useState<ModelParams>(readStoredParams);
  const [source, setSource] = useState(readStoredSource);
  const [fileStatus, setFileStatus] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const [path] = useLocation();

  const analysisState = useMemo(() => {
    if (!events.length) return { result: null, error: null } as { result: AnalysisResult | null; error: string | null };
    try {
      return { result: analyze(events, params), error: null } as { result: AnalysisResult | null; error: string | null };
    } catch (err) {
      return { result: null, error: err instanceof Error ? err.message : 'Analysis could not be completed.' };
    }
  }, [events, params]);
  const result = analysisState.result;
  const selectedRow = result?.rows.find((row) => row.eventId === selectedId) ?? null;

  function updateEvents(next: LoginEvent[], nextSource: string) {
    setEvents(next);
    setSource(nextSource);
    setSelectedId(null);
    try { localStorage.setItem('lpr-events-v1', JSON.stringify(next)); } catch { /* local session remains usable */ }
  }
  function updateParams(next: ModelParams) {
    setParams(next);
    try { localStorage.setItem('lpr-params-v1', JSON.stringify(next)); } catch { /* controls still work in memory */ }
  }
  async function importFile(file?: File) {
    if (!file) return;
    setLoading(true);
    setFileStatus(null);
    try {
      const parsed = parseLoginCsv(await file.text());
      updateEvents(parsed, file.name);
      setFileStatus({ kind: 'success', text: `Imported ${parsed.length.toLocaleString()} events from ${file.name}.` });
    } catch (err) {
      setFileStatus({ kind: 'error', text: err instanceof Error ? err.message : 'This file could not be read.' });
    } finally {
      setLoading(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  }
  function exportEvents() {
    const blob = new Blob([eventsToCsv(events)], { type: 'text/csv;charset=utf-8' });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = href;
    anchor.download = 'login-pattern-events.csv';
    anchor.click();
    URL.revokeObjectURL(href);
  }
  function resetDemo() {
    updateEvents(generateSampleEvents(SEED), 'Generated sample');
    updateParams(DEFAULT_PARAMS);
    setFileStatus({ kind: 'success', text: 'Demo events and model controls have been restored.' });
  }

  const nav = [
    { href: '/', title: 'Overview', icon: Gauge, hint: '01' },
    { href: '/activity', title: 'Activity', icon: Activity, hint: '02' },
    { href: '/test', title: 'Test a login', icon: Sparkles, hint: '03' },
  ];
  const pageTitle = path === '/activity' ? 'Login activity' : path === '/test' ? 'Test a login' : 'Analysis overview';
  return (
    <div className="app-root min-h-[100dvh] text-[#202936]">
      <div className="app-noise" aria-hidden="true" />
      <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
        <div className="brand-lockup">
          <div className="brand-mark"><Fingerprint size={22} strokeWidth={1.7} /></div>
          <div><div className="brand-name">pattern<span>radar</span></div><div className="brand-sub">LOGIN INTELLIGENCE</div></div>
          <button className="mobile-close" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>
        <div className="workspace-label">WORKSPACE <span>LOCAL</span></div>
        <nav className="nav-list" aria-label="Main navigation">
          {nav.map((item) => (
            <Link key={item.href} href={item.href} className={`nav-item ${path === item.href ? 'nav-active' : ''}`} onClick={() => setMobileNav(false)} data-testid={`link-nav-${item.title.toLowerCase().replaceAll(' ', '-')}`}>
              <item.icon size={17} strokeWidth={1.8} /><span>{item.title}</span><small>{item.hint}</small>
            </Link>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-status"><span className="status-dot" /><span><b>Browser-only analysis</b><small>No data leaves this device</small></span></div>
          <div className="sidebar-foot">LPR / 0.8.1 <span>·</span> PRIVATE BY DESIGN</div>
        </div>
      </aside>
      {mobileNav && <button className="mobile-scrim" onClick={() => setMobileNav(false)} aria-label="Close menu overlay" />}
      <main className="main-shell">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={19} /></button>
          <div className="breadcrumb"><span>WORKSPACE</span><i>/</i><b>{pageTitle}</b></div>
          <div className="topbar-right"><span className="local-chip"><span className="status-dot" /> LOCAL ANALYSIS</span><span className="topbar-divider" /><span className="sample-name">{source}</span></div>
        </header>
        <div className="page-body page-enter">
          <div className="page-heading">
            <div><div className="eyebrow"><span className="eyebrow-line" />SIGN-IN BEHAVIOR / {path === '/' ? 'CURRENT READOUT' : path === '/activity' ? 'EVENT EXPLORER' : 'SCENARIO LAB'}</div><h1 className="display">{pageTitle}</h1></div>
            <div className="heading-actions">
              <label className="button button-quiet import-button" htmlFor="csv-import"><FileUp size={15} /> Import CSV</label>
              <input id="csv-import" ref={fileRef} type="file" accept=".csv,text/csv" className="sr-only" onChange={(e) => void importFile(e.target.files?.[0])} data-testid="input-import-csv" />
              <button className="button button-dark" onClick={exportEvents} disabled={!events.length} data-testid="button-export-events"><ArrowDownToLine size={15} /> Export</button>
            </div>
          </div>
          <div className="source-strip"><Info size={14} /><span><b>{source === 'Generated sample' ? 'Generated sample data' : 'Local dataset'}</b> — analysis runs in your browser. No live connection.</span>
            <button onClick={resetDemo} className="reset-link" data-testid="button-reset-demo"><RotateCcw size={13} /> Reset demo</button>
          </div>
          {fileStatus && <div className={`notice ${fileStatus.kind}`} role="status" data-testid="status-import">{fileStatus.kind === 'success' ? <BadgeCheck size={16} /> : <ShieldAlert size={16} />}<span>{fileStatus.text}</span><button onClick={() => setFileStatus(null)} aria-label="Dismiss message"><X size={15} /></button></div>}
          {loading && <div className="loading-bar" role="status"><span /> Reading your local file…</div>}
          <div className="model-controls">
            <div className="control-intro"><SlidersHorizontal size={15} /><b>Model controls</b><span>Re-score as you tune</span></div>
            <label className="control-field"><span>Analysis window</span><select value={params.windowMinutes} onChange={(e) => updateParams({ ...params, windowMinutes: Number(e.target.value) })} data-testid="select-window"><option value={5}>± 5 minutes</option><option value={15}>± 15 minutes</option><option value={30}>± 30 minutes</option><option value={60}>± 60 minutes</option></select></label>
            <label className="control-field contamination-control"><span>Contamination <b className="mono">{Math.round(params.contamination * 100)}%</b></span><input type="range" min="2" max="20" step="1" value={Math.round(params.contamination * 100)} onChange={(e) => updateParams({ ...params, contamination: Number(e.target.value) / 100 })} data-testid="input-contamination" /></label>
            <span className="control-recalc"><span className="recalc-dot" /> LIVE RECALC</span>
          </div>
          {analysisState.error && <div className="error-panel"><ShieldAlert size={21} /><div><b>We couldn’t score these events</b><p>{analysisState.error}</p><button onClick={resetDemo} className="button button-dark"><RotateCcw size={14} /> Restore demo data</button></div></div>}
          {!analysisState.error && !result && <div className="empty-panel"><div className="empty-icon"><Activity size={22} /></div><h2>No events to analyze</h2><p>Import a CSV with at least one successful login, or start again with the generated sample.</p><button className="button button-dark" onClick={resetDemo}>Load demo events <ArrowRight size={15} /></button></div>}
          {result && <Switch>
            <Route path="/activity"><ActivityPage events={events} result={result} search={search} setSearch={setSearch} statusFilter={statusFilter} setStatusFilter={setStatusFilter} selectedId={selectedId} setSelectedId={setSelectedId} selectedRow={selectedRow} /></Route>
            <Route path="/test"><TestPage events={events} result={result} params={params} /></Route>
            <Route path="/"><Overview result={result} params={params} /></Route>
          </Switch>}
          <footer className="page-footer"><span>LOGIN PATTERN RADAR</span><span>Signals, not verdicts. Every flag has a reason.</span></footer>
        </div>
      </main>
    </div>
  );
}

function Overview({ result, params }: { result: AnalysisResult; params: ModelParams }) {
  const { summary } = result;
  const coverage = summary.injected.total ? Math.round(summary.injected.caught / summary.injected.total * 100) : 0;
  const recent = [...result.rows].filter((r) => r.isAnomaly).sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 5);
  const featureCounts = [
    { name: 'Unusual hour', count: result.rows.filter((r) => r.flags.hour).length, color: 'var(--teal)' },
    { name: 'Long absence', count: result.rows.filter((r) => r.flags.days).length, color: 'var(--gold)' },
    { name: 'New location', count: result.rows.filter((r) => r.flags.location).length, color: 'var(--coral)' },
    { name: 'Failed attempts', count: result.rows.filter((r) => r.flags.failed).length, color: 'var(--navy)' },
  ];
  const maxCount = Math.max(1, ...featureCounts.map((f) => f.count));
  return <section className="overview-content">
    <div className="overview-lead">
      <div><div className="lead-kicker"><span className="pulse" /> CURRENT READOUT <span className="lead-date">{new Date().toLocaleDateString('en', { month: 'short', day: 'numeric' })}</span></div><h2>Know what made<br />a login stand out.</h2><p>Each signal is measured against the sign-in patterns in this dataset. Nothing is a verdict on its own.</p></div>
      <div className="lead-number"><span>FLAGGED</span><strong>{String(summary.flagged).padStart(2, '0')}</strong><small>of {summary.successfulLogins.toLocaleString()} successful logins</small><div className="threshold-line"><span>Model threshold</span><b className="mono">{summary.threshold.toFixed(4)}</b></div></div>
      <div className="lead-stamp">L<br /><span>P</span><i>R</i></div>
    </div>
    <div className="metrics-grid">
      <Metric label="Login attempts" value={summary.totalEvents.toLocaleString()} note={`${summary.failedAttempts} unsuccessful`} icon={<Activity size={16} />} />
      <Metric label="People observed" value={summary.users.toLocaleString()} note="distinct user histories" icon={<Fingerprint size={16} />} />
      <Metric label="New locations" value={summary.newLocationLogins.toLocaleString()} note="first seen for this user" icon={<MapPin size={16} />} />
      <Metric label="Injected examples caught" value={summary.injected.total ? `${coverage}%` : '—'} note={summary.injected.total ? `${summary.injected.caught} of ${summary.injected.total} planted examples` : 'No labelled examples'} icon={<ShieldCheck size={16} />} />
    </div>
    <div className="overview-columns">
      <section className="surface signals-surface">
        <div className="section-head"><div><div className="eyebrow small-eyebrow">WHAT MOVES THE NEEDLE</div><h3>Signals in this dataset</h3></div><span className="count-label">{result.rows.length} SCORED</span></div>
        <div className="signal-bars">{featureCounts.map((item) => <div className="signal-row" key={item.name}><div className="signal-title"><span className="signal-key" style={{ background: item.color }} />{item.name}<b>{item.count}</b></div><div className="signal-track"><span style={{ width: `${item.count ? Math.max(4, item.count / maxCount * 100) : 0}%`, background: item.color }} /></div></div>)}</div>
        <div className="signal-caption"><Info size={14} /><span>Signals can overlap. The model combines them to surface the least typical successful logins.</span></div>
      </section>
      <section className="surface recent-surface">
        <div className="section-head"><div><div className="eyebrow small-eyebrow">REVIEW QUEUE</div><h3>Recently flagged</h3></div><Link href="/activity" className="text-link">All activity <ArrowRight size={14} /></Link></div>
        {recent.length ? <div className="recent-list">{recent.map((row) => <Link href="/activity" className="recent-row" key={row.eventId}><div className="review-mark"><ShieldAlert size={15} /></div><div className="recent-main"><b>{row.userId}</b><span>{row.location} <i>·</i> {row.reasons[0] ?? 'Unusual combination of signals'}</span></div><div className="recent-meta"><b className="mono">{row.score.toFixed(3)}</b><span>{shortDate(row.timestamp)}</span></div><ArrowUpRight size={14} className="recent-arrow" /></Link>)}</div> : <div className="empty-inline"><ShieldCheck size={19} /><span>No logins are flagged with these model settings.</span></div>}
        <div className="review-foot"><span>THRESHOLD</span><b className="mono">{result.summary.threshold.toFixed(4)}</b><span>·</span><span>CONTAMINATION</span><b className="mono">{Math.round(params.contamination * 100)}%</b></div>
      </section>
    </div>
    <div className="explain-band"><div className="explain-badge"><Info size={17} /></div><div><b>Explainable by design</b><p>Open any successful login to see the individual signals, their contribution to the score, and the plain-language reason behind a flag.</p></div><Link href="/activity" className="button button-outline">Explore activity <ArrowRight size={15} /></Link></div>
  </section>;
}

function Metric({ label, value, note, icon }: { label: string; value: string; note: string; icon: ReactNode }) {
  return <div className="metric-card"><div className="metric-top"><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><small>{note}</small></div>;
}

function ActivityPage({ events, result, search, setSearch, statusFilter, setStatusFilter, selectedId, setSelectedId, selectedRow }: {
  events: LoginEvent[]; result: AnalysisResult; search: string; setSearch: (s: string) => void;
  statusFilter: string; setStatusFilter: (s: string) => void; selectedId: string | null;
  setSelectedId: (s: string | null) => void; selectedRow: ScoredRow | null;
}) {
  const rowById = new Map(result.rows.map((r) => [r.eventId, r]));
  const filtered = [...events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).filter((event) => {
    const row = rowById.get(event.id);
    const queryMatch = `${event.userId} ${event.location} ${event.timestamp}`.toLowerCase().includes(search.toLowerCase());
    const statusMatch = statusFilter === 'all' || (statusFilter === 'failed' ? !event.success : statusFilter === 'flagged' ? !!row?.isAnomaly : statusFilter === 'normal' ? !!row && !row.isAnomaly : event.success);
    return queryMatch && statusMatch;
  });
  const chooseRow = (event: LoginEvent) => {
    if (!event.success) return;
    setSelectedId(selectedId === event.id ? null : event.id);
  };
  return <section className="activity-layout">
    <div className="activity-toolbar">
      <div className="activity-count"><b>{filtered.length.toLocaleString()}</b><span>events shown</span><i>·</i><span>{result.summary.flagged} flagged</span></div>
      <div className="filter-controls">
        <label className="search-box"><Search size={15} /><input type="search" placeholder="Search user or location" value={search} onChange={(e) => setSearch(e.target.value)} data-testid="input-search-events" /><kbd>/</kbd></label>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Filter event status" data-testid="select-event-filter"><option value="all">All events</option><option value="flagged">Flagged logins</option><option value="normal">Not flagged</option><option value="failed">Failed attempts</option><option value="success">Successful logins</option></select>
      </div>
    </div>
    <div className={`activity-grid ${selectedRow ? 'has-detail' : ''}`}>
      <div className="surface table-surface">
        <div className="table-wrap scrollbar-thin"><table><thead><tr><th>RESULT</th><th>USER</th><th>WHEN <span>UTC</span></th><th>LOCATION</th><th>SCORE</th><th></th></tr></thead><tbody>
          {filtered.map((event) => {
            const row = rowById.get(event.id);
            const isSelected = selectedId === event.id;
            return <tr key={event.id} onClick={() => chooseRow(event)} className={`${event.success ? 'selectable-row' : ''} ${isSelected ? 'row-selected' : ''} ${row?.isAnomaly ? 'flag-row' : ''}`} data-testid={`row-event-${event.id}`}>
              <td><StatusPill event={event} row={row} /></td><td className="user-cell">{event.userId}</td><td className="date-cell">{shortDate(event.timestamp)}</td><td>{event.location}</td><td className="score-cell">{row ? <span className={`score-value ${row.isAnomaly ? 'score-hot' : ''}`}>{row.score.toFixed(3)}</span> : <span className="no-score">—</span>}</td><td>{event.success && <ArrowUpRight size={14} className="row-open" />}</td>
            </tr>;
          })}
        </tbody></table>
        {!filtered.length && <div className="table-empty"><div className="empty-icon"><Search size={18} /></div><b>No matching events</b><span>Try another search or filter, or reset the controls.</span><button onClick={() => { setSearch(''); setStatusFilter('all'); }} className="text-link">Clear filters</button></div>}
        </div>
        <div className="table-bottom"><span>Showing {filtered.length.toLocaleString()} of {events.length.toLocaleString()} events</span><span>Successful logins are selectable</span></div>
      </div>
      {selectedRow ? <ExplanationPanel row={selectedRow} threshold={result.summary.threshold} onClose={() => setSelectedId(null)} /> : <div className="detail-placeholder"><div className="detail-illustration"><Activity size={21} /></div><span className="eyebrow small-eyebrow">SIGNAL BREAKDOWN</span><h3>Select a successful<br />login to inspect it.</h3><p>See how hour, history, location, and nearby failed attempts shaped its score.</p><div className="placeholder-keys"><span>01 / HOUR</span><span>02 / HISTORY</span><span>03 / LOCATION</span><span>04 / ATTEMPTS</span></div></div>}
    </div>
  </section>;
}

function StatusPill({ event, row }: { event: LoginEvent; row?: ScoredRow }) {
  if (!event.success) return <span className="pill pill-failed"><span />Failed</span>;
  if (row?.isAnomaly) return <span className="pill pill-flagged"><span />Flagged</span>;
  return <span className="pill pill-ok"><span />Within pattern</span>;
}

const signalMeta = [
  { key: 'hour' as const, label: 'Unusual hour', detail: (r: ScoredRow) => `${String(r.hourOfDay).padStart(2, '0')}:00 UTC`, icon: Clock3 },
  { key: 'days' as const, label: 'Time away', detail: (r: ScoredRow) => r.daysSinceLastLogin === null ? 'First login' : `${Math.round(r.daysSinceLastLogin)} days`, icon: Activity },
  { key: 'location' as const, label: 'Location', detail: (r: ScoredRow) => r.location, icon: MapPin },
  { key: 'failed' as const, label: 'Failed attempts', detail: (r: ScoredRow) => `${r.failedAttemptCount} nearby`, icon: ShieldAlert },
];
function ExplanationPanel({ row, threshold, onClose }: { row: ScoredRow; threshold: number; onClose: () => void }) {
  const parts = signalMeta.map((signal) => ({ ...signal, amount: row.contributions[signal.key], flagged: row.flags[signal.key] }));
  const total = Math.max(...parts.map((p) => p.amount), 0.0001);
  return <aside className="explanation-panel" aria-label="Login explanation" data-testid="panel-explanation">
    <div className="explain-top"><div><div className="eyebrow small-eyebrow">LOGIN EXPLANATION</div><div className="explain-user">{row.userId}</div></div><button className="icon-button" onClick={onClose} aria-label="Close explanation"><X size={17} /></button></div>
    <div className="explain-location"><MapPin size={14} />{row.location}<span>·</span>{fmt(row.timestamp)}</div>
    <div className={`verdict ${row.isAnomaly ? 'verdict-flagged' : 'verdict-ok'}`}><div>{row.isAnomaly ? <ShieldAlert size={18} /> : <ShieldCheck size={18} />}</div><span><b>{row.isAnomaly ? 'Flagged as unusual' : 'Within expected pattern'}</b><small>{row.isAnomaly ? 'This login crossed the current model threshold.' : 'This login scored below the current threshold.'}</small></span></div>
    <div className="score-dial-row"><div><span>ANOMALY SCORE</span><b className="mono">{row.score.toFixed(4)}</b></div><div className="score-meter"><span style={{ width: `${Math.min(100, row.score * 100)}%` }} /></div><div className="threshold-read"><span>THRESHOLD</span><b className="mono">{row.isAnomaly ? '≥' : '<'} {threshold.toFixed(4)}</b></div></div>
    <div className="detail-section-title"><b>Signal by signal</b><span>CONTRIBUTION</span></div>
    <div className="contribution-list">{parts.map((part) => <div className={`contribution-row ${part.flagged ? 'contribution-active' : ''}`} key={part.key}><div className="contribution-head"><span className="contribution-icon"><part.icon size={14} /></span><span className="contribution-name">{part.label}<small>{part.detail(row)}</small></span><span className="contribution-score mono">{part.amount.toFixed(4)}</span></div><div className="contribution-track"><span style={{ width: `${part.amount ? Math.max(3, part.amount / total * 100) : 0}%` }} /></div></div>)}</div>
    <div className="reason-box"><div className="reason-heading"><Info size={14} /> WHY IT MATTERS</div>{row.reasons.length ? <ul>{row.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p>No single signal crossed its individual alert condition. The model score reflects the combined pattern.</p>}</div>
    <div className="explain-foot"><span>EVENT ID</span><code>{row.eventId}</code></div>
  </aside>;
}

function TestPage({ events, result, params }: { events: LoginEvent[]; result: AnalysisResult; params: ModelParams }) {
  const defaultUser = result.users[0]?.userId ?? '';
  const [userId, setUserId] = useState(defaultUser);
  const [location, setLocation] = useState(result.users[0]?.knownLocations[0] ?? '');
  const [when, setWhen] = useState('2026-11-10T09:00');
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    if (result.users.length && !result.users.some((user) => user.userId === userId)) {
      setUserId(result.users[0]!.userId);
      setLocation(result.users[0]!.knownLocations[0] ?? '');
      setProbeResult(null);
    }
  }, [result.users, userId]);
  const presets = [
    { name: 'Usual morning', desc: 'Known place, familiar hour', time: '2026-11-10T09:00', attempts: 0, place: 'known' },
    { name: 'Late night', desc: 'Same place, unusual hour', time: '2026-11-10T02:20', attempts: 0, place: 'known' },
    { name: 'New location', desc: 'Known hour, new place', time: '2026-11-10T09:00', attempts: 0, place: 'new' },
    { name: 'Password burst', desc: 'Several failures beforehand', time: '2026-11-10T09:00', attempts: 7, place: 'known' },
  ];
  const person = result.users.find((u) => u.userId === userId);
  function setPreset(preset: typeof presets[number]) {
    setWhen(preset.time); setFailedAttempts(preset.attempts);
    setLocation(preset.place === 'new' ? 'Lagos, NG' : person?.knownLocations[0] ?? '');
    setProbeResult(null); setError('');
  }
  function runSimulation() {
    setError(''); setProbeResult(null);
    try {
      const scored = scoreProbe(events, params, { userId, timestamp: new Date(when).toISOString(), location: location.trim(), failedAttempts });
      setProbeResult(scored);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'This scenario could not be scored.');
    }
  }
  return <section className="test-layout">
    <div className="test-intro"><div className="eyebrow small-eyebrow">A SAFE PLACE TO ASK WHAT IF</div><h2>Change one thing.<br /><em>See what moves.</em></h2><p>Score a hypothetical sign-in against one person’s history in the current dataset. This does not create an event or change your data.</p><div className="test-trust"><ShieldCheck size={15} />Runs locally against the selected user’s history</div></div>
    <div className="test-workspace">
      <div className="surface scenario-form">
        <div className="form-head"><div><div className="eyebrow small-eyebrow">SCENARIO INPUT</div><h3>Describe the login</h3></div><span className="step-number">01—04</span></div>
        <div className="preset-list"><span className="field-label">START WITH A SCENARIO</span><div className="preset-grid">{presets.map((preset) => <button key={preset.name} className="preset-button" onClick={() => setPreset(preset)} data-testid={`button-preset-${preset.name.toLowerCase().replaceAll(' ', '-')}`}><b>{preset.name}</b><span>{preset.desc}</span><ArrowUpRight size={13} /></button>)}</div></div>
        <div className="form-fields">
          <label className="field-block"><span className="field-label">PERSON</span><select value={userId} onChange={(e) => { setUserId(e.target.value); setProbeResult(null); }} data-testid="select-probe-user">{result.users.map((u) => <option key={u.userId} value={u.userId}>{u.userId} · {u.logins} logins</option>)}</select><small>{person ? `${person.logins} successful logins · usual around ${String(Math.round(person.typicalHour)).padStart(2, '0')}:00 UTC` : 'No history available'}</small></label>
          <div className="field-pair"><label className="field-block"><span className="field-label">WHEN <i>LOCAL TIME</i></span><input type="datetime-local" value={when} onChange={(e) => { setWhen(e.target.value); setProbeResult(null); }} data-testid="input-probe-time" /></label>
            <label className="field-block"><span className="field-label">WHERE</span><input value={location} onChange={(e) => { setLocation(e.target.value); setProbeResult(null); }} placeholder="City, country" data-testid="input-probe-location" /></label></div>
          <label className="field-block attempts-field"><span className="field-label">FAILED ATTEMPTS JUST BEFORE <b>{failedAttempts}</b></span><input type="range" min="0" max="12" value={failedAttempts} onChange={(e) => { setFailedAttempts(Number(e.target.value)); setProbeResult(null); }} data-testid="input-probe-attempts" /><div className="range-labels"><span>None</span><span>12 attempts</span></div></label>
        </div>
        <div className="form-submit"><span><Info size={14} /> Scored against {result.users.length} user histories</span><button className="button button-dark run-button" onClick={runSimulation} disabled={!userId || !location.trim() || !when} data-testid="button-run-simulation"><Sparkles size={15} /> Score this login <ArrowRight size={15} /></button></div>
        {error && <div className="notice error"><ShieldAlert size={15} />{error}</div>}
      </div>
      <div className={`surface probe-result ${probeResult ? 'result-ready' : ''}`}>
        {probeResult ? <ProbeExplanation probe={probeResult} /> : <div className="result-prompt"><div className="result-radar"><span /><span /><i><Gauge size={19} /></i></div><span className="eyebrow small-eyebrow">SCENARIO RESULT</span><h3>Waiting for your<br />first scenario.</h3><p>Choose a preset or enter the sign-in details. The explanation will show what changed the score.</p><div className="result-prompt-foot"><span>THRESHOLD</span><b className="mono">{result.summary.threshold.toFixed(4)}</b></div></div>}
      </div>
    </div>
    <div className="test-note"><Info size={15} /><p><b>How to read this:</b> A score at or above the threshold is flagged by the current model. Contributions show how much each feature influenced the result; they are not probabilities or proof of risk.</p></div>
  </section>;
}

function ProbeExplanation({ probe }: { probe: ProbeResult }) {
  const row = probe.row;
  return <div className="probe-explanation" data-testid="panel-probe-result">
    <div className="probe-result-head"><span className="eyebrow small-eyebrow">SCENARIO RESULT</span><span className="result-check"><BadgeCheck size={15} /> SCORED</span></div>
    <div className={`probe-verdict ${row.isAnomaly ? 'probe-alert' : ''}`}><div className="probe-score mono">{row.score.toFixed(3)}</div><div><b>{row.isAnomaly ? 'This login would be flagged.' : 'This login fits the pattern.'}</b><span>{row.isAnomaly ? 'Its score meets or exceeds the model threshold.' : 'Its score falls below the model threshold.'}</span></div></div>
    <div className="probe-threshold"><span>MODEL THRESHOLD</span><div className="probe-track"><span style={{ left: `${Math.min(94, probe.threshold * 100)}%` }} /><i style={{ width: `${Math.min(100, row.score * 100)}%` }} /></div><b className="mono">{probe.threshold.toFixed(4)}</b></div>
    {probe.profile && <div className="profile-strip"><Fingerprint size={15} /><span><b>{probe.profile.userId}</b><small>History: {probe.profile.logins} successful sign-ins · {probe.profile.knownLocations.length} known locations</small></span><span className="profile-hours">TYPICAL HOUR <b className="mono">{String(Math.round(probe.profile.typicalHour)).padStart(2, '0')}:00</b></span></div>}
    <div className="probe-signals-title"><b>What shaped the score</b><span>FEATURE CONTRIBUTION</span></div>
    <div className="probe-signal-list">{signalMeta.map((signal) => {
      const Icon = signal.icon;
      const amount = row.contributions[signal.key];
      return <div className={`probe-signal ${row.flags[signal.key] ? 'probe-signal-on' : ''}`} key={signal.key}><span className="probe-signal-icon"><Icon size={14} /></span><span className="probe-signal-name">{signal.label}<small>{signal.detail(row)}</small></span><span className="probe-signal-bar"><i style={{ width: `${Math.min(100, amount / Math.max(...Object.values(row.contributions), 0.0001) * 100)}%` }} /></span><b className="mono">{amount.toFixed(4)}</b></div>;
    })}</div>
    <div className="probe-reasons">{row.reasons.length ? row.reasons.map((reason) => <div key={reason}><ShieldAlert size={14} /><span>{reason}</span></div>) : <div><ShieldCheck size={14} /><span>No individual signal crossed its alert condition.</span></div>}</div>
    <div className="probe-foot"><span>SCORE PERCENTILE</span><b className="mono">{probe.scorePercentile.toFixed(1)}th</b><span>·</span><span>NOT A PROBABILITY</span></div>
  </div>;
}

export default App;
