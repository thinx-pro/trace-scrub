import { createHash } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeSync, chmodSync } from 'node:fs';
import { basename, dirname, extname, join } from 'node:path';
import { DETECTORS, PREFILTER, isPlaceholder, looksRandom, mask, rejectGeneric, secretOf } from './detectors.js';

export const fingerprint = (v) => createHash('sha256').update(String(v)).digest('hex').slice(0, 10);

const BINARY_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.zip', '.gz', '.tgz', '.br', '.zst', '.woff', '.woff2', '.ttf', '.mp4', '.mov', '.mp3', '.wav', '.so', '.dylib', '.node', '.wasm', '.bin', '.gguf', '.safetensors', '.pt']);
const SQLITE_RE = /\.(sqlite3?|db)(-wal)?$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__', '.venv', 'venv']);

function* walk(p, opts, depth = 0) {
  let st;
  try { st = statSync(p); } catch { return; }
  if (st.isFile()) { yield { path: p, st }; return; }
  if (!st.isDirectory() || depth > 12) return;
  let names;
  try { names = readdirSync(p); } catch { return; }
  for (const n of names) {
    if (SKIP_DIRS.has(n)) continue;
    const child = join(p, n);
    if (opts.sqliteOnly) {
      if (!SQLITE_RE.test(n)) continue;
      try { const s = statSync(child); if (s.isFile()) yield { path: child, st: s }; } catch { /* gone */ }
      continue;
    }
    yield* walk(child, opts, depth + 1);
  }
}

// Find all secrets in a text blob. Returns [{det, value, start, end}] with overlaps removed
// (a specific detector wins over a generic one covering the same span).
export function findSecrets(text) {
  if (!PREFILTER.test(text)) return [];
  const hits = [];
  for (const det of DETECTORS) {
    det.re.lastIndex = 0;
    for (const m of text.matchAll(det.re)) {
      const { value, start } = secretOf(det, m);
      if (det.id !== 'private-key' && isPlaceholder(value, !!det.generic)) continue;
      if (det.generic && (rejectGeneric(det, m, value) || (det.id === 'env-assign' && !looksRandom(value)))) continue;
      hits.push({ det, value, start, end: start + value.length });
    }
  }
  hits.sort((a, b) => a.start - b.start || (a.det.generic ? 1 : 0) - (b.det.generic ? 1 : 0) || b.end - a.end);
  const out = [];
  let lastEnd = -1;
  for (const h of hits) {
    if (h.start < lastEnd) continue;
    out.push(h);
    lastEnd = h.end;
  }
  return out;
}

export const redactionFor = (det, value) => `[REDACTED:${det.id}:${fingerprint(value)}]`;

export function redactText(text, hits) {
  let out = '';
  let pos = 0;
  for (const h of hits) {
    out += text.slice(pos, h.start) + redactionFor(h.det, h.value);
    pos = h.end;
  }
  return out + text.slice(pos);
}

const lineOf = (text, idx) => { let n = 1; for (let i = text.indexOf('\n'); i !== -1 && i < idx; i = text.indexOf('\n', i + 1)) n++; return n; };

// Fingerprints of credentials currently configured on this machine (never returned as values).
export function liveFingerprints(files, env = {}) {
  const live = new Map();
  for (const f of files) {
    let t;
    try { if (!existsSync(f) || statSync(f).size > 2_000_000) continue; t = readFileSync(f, 'utf8'); } catch { continue; }
    for (const h of findSecrets(t)) live.set(fingerprint(h.value), basename(f));
  }
  for (const [k, v] of Object.entries(env)) {
    if (!v || v.length < 12) continue;
    for (const h of findSecrets(`${k}=${v}`)) live.set(fingerprint(h.value), `$${k}`);
  }
  return live;
}

export function scan({ sources, maxBytes = 256 * 1024 * 1024, sinceMs = 0, onFile } = {}) {
  const findings = new Map(); // fp -> finding
  const perSource = [];
  const skipped = [];
  const filesWithHits = [];
  for (const src of sources) {
    const stat = { ...src, files: 0, bytes: 0, filesWithHits: 0, secrets: new Set(), present: existsSync(src.path) };
    perSource.push(stat);
    if (!stat.present) continue;
    for (const { path, st } of walk(src.path, src)) {
      if (BINARY_EXT.has(extname(path).toLowerCase())) continue;
      if (sinceMs && st.mtimeMs < sinceMs) continue;
      if (st.size > maxBytes) { skipped.push({ path, reason: `larger than ${Math.round(maxBytes / 1048576)} MB` }); continue; }
      const sqlite = SQLITE_RE.test(path);
      let text;
      try {
        const buf = readFileSync(path);
        if (!sqlite && buf.subarray(0, 8000).includes(0)) continue; // binary
        text = buf.toString(sqlite ? 'latin1' : 'utf8');
      } catch (e) { skipped.push({ path, reason: e.code || 'unreadable' }); continue; }
      stat.files++;
      stat.bytes += st.size;
      onFile?.(path);
      const hits = findSecrets(text);
      if (!hits.length) continue;
      stat.filesWithHits++;
      filesWithHits.push({ path, sqlite, hits: hits.length, mtimeMs: st.mtimeMs, agent: src.agent });
      for (const h of hits) {
        const fp = fingerprint(h.value);
        stat.secrets.add(fp);
        let f = findings.get(fp);
        if (!f) {
          f = { fp, rule: h.det.id, name: h.det.name, sev: h.det.sev, rotate: h.det.rotate, masked: mask(h.value, h.det.keep), occurrences: 0, files: new Set(), agents: new Set(), first: { path, line: lineOf(text, h.start) }, lastSeenMs: 0, firstSeenMs: Infinity };
          findings.set(fp, f);
        }
        f.occurrences++;
        f.files.add(path);
        f.agents.add(src.agent);
        f.lastSeenMs = Math.max(f.lastSeenMs, st.mtimeMs);
        f.firstSeenMs = Math.min(f.firstSeenMs, st.mtimeMs);
      }
    }
  }
  return { findings: [...findings.values()], perSource, skipped, filesWithHits };
}

// Rewrite one file with secrets replaced. Atomic (temp file + rename), keeps the mode.
// SQLite files are never rewritten.
export function redactFile(path) {
  if (SQLITE_RE.test(path)) return { path, skipped: 'sqlite (redact by deleting the database or via its app)' };
  const st = statSync(path);
  const text = readFileSync(path, 'utf8');
  const hits = findSecrets(text);
  if (!hits.length) return { path, replaced: 0 };
  const out = redactText(text, hits);
  const tmp = join(dirname(path), `.${basename(path)}.trace-scrub.${process.pid}.tmp`);
  const fd = openSync(tmp, 'w', st.mode & 0o777);
  try { writeSync(fd, out); fsyncSync(fd); } finally { closeSync(fd); }
  chmodSync(tmp, st.mode & 0o777);
  const now = statSync(path);
  if (now.size !== st.size || now.mtimeMs !== st.mtimeMs) {
    rmSync(tmp, { force: true });
    return { path, skipped: 'file changed while redacting (session still active?) — run again later' };
  }
  renameSync(tmp, path);
  return { path, replaced: hits.length };
}
