const useColor = () => process.env.FORCE_COLOR === '1' || (process.stdout.isTTY && !process.env.NO_COLOR);
const c = (code) => (s) => (useColor() ? `\x1b[${code}m${s}\x1b[0m` : String(s));
export const bold = c(1), dim = c(2), red = c(31), green = c(32), yellow = c(33), magenta = c(35), cyan = c(36);

const vlen = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '').length;
const pad = (s, n) => String(s) + ' '.repeat(Math.max(0, n - vlen(s)));
const day = (ms) => (Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString().slice(0, 10) : '-');
const mb = (b) => (b >= 1048576 ? `${(b / 1048576).toFixed(b >= 10485760 ? 0 : 1)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`);
const sevTag = (s) => (s >= 3 ? red('HIGH') : s === 2 ? yellow('MED ') : dim('LOW '));

function table(rows, header) {
  const w = header.map((h, i) => Math.max(vlen(h), ...rows.map((r) => vlen(r[i]))));
  const line = (r) => '  ' + r.map((x, i) => pad(x, w[i])).join('  ').trimEnd();
  return [line(header.map((h) => bold(h))), ...rows.map(line)].join('\n');
}

export function sortFindings(findings) {
  return findings.sort((a, b) => (b.live ? 1 : 0) - (a.live ? 1 : 0) || b.sev - a.sev || b.occurrences - a.occurrences);
}

export function renderText(res, { home, version, redactPlan } = {}) {
  const tilde = (p) => (home && p.startsWith(home) ? '~' + p.slice(home.length) : p);
  const out = [];
  out.push(`${bold('trace-scrub')} ${dim(version)} ${dim('— secrets that leaked into agent transcripts & logs (values are never printed)')}`);
  out.push('');
  const present = res.perSource.filter((s) => s.present && s.files);
  if (!present.length) {
    out.push(yellow('  No agent transcripts found. Use --path <dir|file> to scan gateway logs or memory folders.'));
  } else {
    out.push(table(present.map((s) => [s.agent, s.kind, `${s.files.toLocaleString('en-US')} file${s.files === 1 ? '' : 's'}`, mb(s.bytes), s.filesWithHits ? red(`${s.filesWithHits} with secrets`) : green('clean')]),
      ['SOURCE', 'WHAT', 'FILES', 'SIZE', 'RESULT']));
  }
  out.push('');
  const f = res.findings;
  if (!f.length) {
    out.push(green('  ✓ No credentials found in the scanned transcripts and logs.'));
    return out.join('\n');
  }
  const occ = f.reduce((n, x) => n + x.occurrences, 0);
  const live = f.filter((x) => x.live).length;
  out.push(bold(`  ${f.length} distinct secret${f.length > 1 ? 's' : ''}`) + ` in ${res.filesWithHits.length} file${res.filesWithHits.length > 1 ? 's' : ''} (${occ} occurrences)` + (live ? ', ' + red(bold(`${live} still configured on this machine`)) : ''));
  out.push('');
  out.push(table(f.map((x) => [
    sevTag(x.sev), x.name, cyan(x.masked), [...x.agents].join(', '), String(x.files.size), String(x.occurrences), day(x.lastSeenMs),
    x.live ? red(`LIVE (${x.live})`) : dim('not in current config'),
  ]), ['SEV', 'TYPE', 'VALUE', 'FOUND IN', 'FILES', 'OCC', 'LAST SEEN', 'STATUS']));
  out.push('');
  out.push(bold('  Where (first sighting of each):'));
  for (const x of f.slice(0, 12)) out.push(`  ${dim(x.fp)}  ${tilde(x.first.path)}${dim(':' + x.first.line)}`);
  if (f.length > 12) out.push(dim(`  … ${f.length - 12} more (use --json)`));
  out.push('');
  out.push(bold('  Next steps'));
  out.push(`  1. ${bold('Rotate first')}, scrub second: anything that ever sat in a transcript may also be in a gateway log, a synced memory repo or a backup.`);
  const seen = new Set();
  for (const x of f) {
    if (seen.has(x.rule)) continue;
    seen.add(x.rule);
    out.push(`     ${x.live ? red('•') : '•'} ${x.name}: ${dim(x.rotate)}`);
  }
  if (redactPlan) {
    out.push(`  2. ${bold('Scrub:')} ${redactPlan}`);
  } else {
    out.push(`  2. ${bold('Scrub:')} ${cyan('trace-scrub --redact')} shows what would change; add ${cyan('--yes')} to rewrite files (values → [REDACTED:type:fingerprint]).`);
  }
  out.push(`  3. ${bold('Stop new leaks:')} keep tokens out of tool output (no ${cyan('gh auth token')}, ${cyan('env')}, ${cyan('cat .env')} in agent shells);\n     if you run an LLM gateway, turn off response-body logging or pipe it through ${cyan('trace-scrub --stdin --redact')}.`);
  return out.join('\n');
}

export function toJSON(res, { home } = {}) {
  const tilde = (p) => (home && p.startsWith(home) ? '~' + p.slice(home.length) : p);
  return {
    sources: res.perSource.filter((s) => s.present).map((s) => ({ agent: s.agent, kind: s.kind, path: tilde(s.path), files: s.files, bytes: s.bytes, filesWithSecrets: s.filesWithHits, distinctSecrets: s.secrets.size })),
    findings: res.findings.map((x) => ({
      fingerprint: x.fp, rule: x.rule, type: x.name, severity: x.sev, masked: x.masked, live: x.live || null, occurrences: x.occurrences,
      agents: [...x.agents], files: [...x.files].map(tilde), firstSighting: { path: tilde(x.first.path), line: x.first.line },
      firstSeen: day(x.firstSeenMs), lastSeen: day(x.lastSeenMs), rotate: x.rotate,
    })),
    skipped: res.skipped.map((s) => ({ ...s, path: tilde(s.path) })),
  };
}

export function toMarkdown(res, opts) {
  const j = toJSON(res, opts);
  const rows = j.findings.map((x) => `| ${x.severity >= 3 ? 'HIGH' : x.severity === 2 ? 'MED' : 'LOW'} | ${x.type} | \`${x.masked}\` | ${x.agents.join(', ')} | ${x.files.length} | ${x.occurrences} | ${x.lastSeen} | ${x.live ? 'LIVE' : '-'} |`);
  return [
    '## trace-scrub report', '',
    `Scanned ${j.sources.reduce((n, s) => n + s.files, 0)} files from ${j.sources.filter((s) => s.files).map((s) => `${s.agent} ${s.kind}`).join(', ') || 'no sources'}.`, '',
    j.findings.length ? '| Sev | Type | Value | Found in | Files | Occ | Last seen | Live |\n|---|---|---|---|---|---|---|---|\n' + rows.join('\n') : 'No credentials found.',
    '',
  ].join('\n');
}
