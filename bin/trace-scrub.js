#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { defaultSources, liveCredentialFiles } from '../src/sources.js';
import { findSecrets, fingerprint, liveFingerprints, redactFile, redactText, scan } from '../src/scan.js';
import { bold, cyan, dim, green, red, renderText, sortFindings, toJSON, toMarkdown, yellow } from '../src/report.js';
import { mask } from '../src/detectors.js';

const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

const HELP = `trace-scrub ${VERSION}
Find credentials that leaked into AI agent transcripts, gateway logs and memory folders,
and (optionally) redact them in place. Offline, read-only by default, never prints values.

Usage
  npx trace-scrub [options]

What gets scanned by default
  Claude Code (~/.claude/projects, history, paste-cache, file-history, shell-snapshots, debug),
  Codex (~/.codex/sessions, archived_sessions, history, memories, *.sqlite logs),
  Gemini CLI (~/.gemini/tmp), OpenCode (~/.local/share/opencode), Cline / Roo Code tasks, Aider history.

Options
  --path <p>          Also scan this file or folder (gateway logs, memory repo, exported DB dump). Repeatable.
  --only              Scan only the --path targets, not the default agent locations.
  --stdin             Read text from stdin (e.g. a log stream). With --redact, writes the redacted text to stdout.
  --since <days>      Only files modified in the last N days.
  --redact            Show which files would be rewritten (dry run).
  --redact --yes      Rewrite files: each secret becomes [REDACTED:<type>:<fingerprint>]. SQLite files are never touched.
  --include-active    With --redact: also rewrite files modified in the last 10 minutes (live sessions are skipped by default).
  --no-live           Don't fingerprint the credentials currently configured on this machine
                      (credential files, secret-named env vars, \`gh auth token\`).
  --json | --md       Machine-readable / Markdown output.
  --max-mb <n>        Skip files larger than n MB (default 256).
  --home <dir>        Use another home directory (testing, or scanning a mounted backup).
  -h, --help | -v, --version

Exit codes: 0 nothing found, 1 secrets found, 2 usage error.
`;

function parse(argv) {
  const o = { paths: [], only: false, stdin: false, since: 0, redact: false, yes: false, active: false, live: true, json: false, md: false, maxMb: 256, home: homedir() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    switch (a) {
      case '--path': o.paths.push(resolve(val())); break;
      case '--only': o.only = true; break;
      case '--stdin': o.stdin = true; break;
      case '--since': o.since = Number(val()); if (!(o.since > 0)) throw new Error('--since needs a positive number of days'); break;
      case '--redact': o.redact = true; break;
      case '--yes': case '-y': o.yes = true; break;
      case '--include-active': o.active = true; break;
      case '--no-live': o.live = false; break;
      case '--json': o.json = true; break;
      case '--md': o.md = true; break;
      case '--max-mb': o.maxMb = Number(val()); break;
      case '--home': o.home = resolve(val()); break;
      case '-h': case '--help': o.help = true; break;
      case '-v': case '--version': o.version = true; break;
      default: throw new Error(`unknown option ${a}`);
    }
  }
  if (o.only && !o.paths.length && !o.stdin) throw new Error('--only needs at least one --path');
  return o;
}

function readStdin() {
  try { return readFileSync(0, 'utf8'); } catch { return ''; }
}

function main() {
  let o;
  try { o = parse(process.argv.slice(2)); } catch (e) { console.error(`trace-scrub: ${e.message}\n\n${HELP}`); return 2; }
  if (o.help) { console.log(HELP); return 0; }
  if (o.version) { console.log(VERSION); return 0; }

  if (o.stdin) {
    const text = readStdin();
    const hits = findSecrets(text);
    if (o.redact) { process.stdout.write(redactText(text, hits)); if (hits.length) console.error(`trace-scrub: redacted ${hits.length} secret(s)`); return hits.length ? 1 : 0; }
    const rows = hits.map((h) => ({ fingerprint: fingerprint(h.value), rule: h.det.id, type: h.det.name, masked: mask(h.value, h.det.keep) }));
    if (o.json) console.log(JSON.stringify({ findings: rows }, null, 2));
    else if (!rows.length) console.log(green('✓ No credentials found on stdin.'));
    else for (const r of rows) console.log(`${dim(r.fingerprint)}  ${r.type}  ${cyan(r.masked)}`);
    return rows.length ? 1 : 0;
  }

  const sources = [
    ...(o.only ? [] : defaultSources(o.home)),
    ...o.paths.map((p) => ({ agent: 'custom', kind: p.startsWith(o.home) ? '~' + p.slice(o.home.length) : p, path: p })),
  ];
  const tty = process.stderr.isTTY && !o.json && !o.md;
  let n = 0;
  const res = scan({
    sources, maxBytes: o.maxMb * 1048576, sinceMs: o.since ? Date.now() - o.since * 86400000 : 0,
    onFile: tty ? () => { if (++n % 200 === 0) process.stderr.write(`\r  scanning… ${n} files`); } : undefined,
  });
  if (tty && n >= 200) process.stderr.write('\r' + ' '.repeat(40) + '\r');

  if (o.live) {
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => /KEY|TOKEN|SECRET|PASS/i.test(k)));
    const live = liveFingerprints(liveCredentialFiles(o.home), o.home === homedir() ? env : {});
    // gh on macOS/Windows keeps its token in the system keychain, not hosts.yml; fingerprint it in-process.
    if (o.home === homedir()) {
      try {
        const tok = execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
        for (const h of findSecrets(tok)) live.set(fingerprint(h.value), 'gh keychain');
      } catch { /* gh not installed or not logged in */ }
    }
    for (const f of res.findings) if (live.has(f.fp)) f.live = live.get(f.fp);
  }
  sortFindings(res.findings);

  let redactPlan = null;
  if (o.redact) {
    const cutoff = Date.now() - 10 * 60000;
    const targets = res.filesWithHits.filter((f) => !f.sqlite && (o.active || f.mtimeMs < cutoff));
    const active = res.filesWithHits.filter((f) => !f.sqlite && !o.active && f.mtimeMs >= cutoff);
    const sqlite = res.filesWithHits.filter((f) => f.sqlite);
    const total = targets.reduce((x, f) => x + f.hits, 0);
    if (!o.yes) {
      redactPlan = `dry run — ${bold(targets.length)} file(s) / ${total} occurrence(s) would be rewritten` +
        (active.length ? `; ${active.length} active file(s) skipped (--include-active)` : '') +
        (sqlite.length ? `; ${sqlite.length} SQLite file(s) can't be rewritten safely` : '') + `. Re-run with ${cyan('--redact --yes')}.`;
    } else {
      let done = 0, files = 0;
      const problems = [];
      for (const t of targets) {
        try {
          const r = redactFile(t.path);
          if (r.skipped) problems.push(`${t.path}: ${r.skipped}`); else { done += r.replaced; files++; }
        } catch (e) { problems.push(`${t.path}: ${e.code || e.message}`); }
      }
      redactPlan = green(`rewrote ${files} file(s), ${done} occurrence(s) replaced.`) +
        (active.length ? yellow(` ${active.length} active file(s) skipped.`) : '') +
        (sqlite.length ? yellow(` ${sqlite.length} SQLite file(s) left as-is.`) : '') +
        (problems.length ? '\n     ' + red(problems.join('\n     ')) : '') +
        `\n     ${dim('Rotating is still required: redaction only cleans this machine\'s copies.')}`;
    }
  }

  if (o.json) console.log(JSON.stringify(toJSON(res, { home: o.home }), null, 2));
  else if (o.md) console.log(toMarkdown(res, { home: o.home }));
  else console.log(renderText(res, { home: o.home, version: VERSION, redactPlan }));
  return res.findings.length ? 1 : 0;
}

process.exitCode = main();
