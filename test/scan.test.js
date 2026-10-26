import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeHome, makeTokens } from './fixture.js';
import { findSecrets, fingerprint } from '../src/scan.js';

const BIN = fileURLToPath(new URL('../bin/trace-scrub.js', import.meta.url));
const run = (args, input) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', input, env: { PATH: process.env.PATH } });

function withHome(fn) {
  const home = mkdtempSync(join(tmpdir(), 'ts-test-'));
  try { return fn(home, makeHome(home)); } finally { rmSync(home, { recursive: true, force: true }); }
}

test('finds every planted secret type and nothing in the clean file', () => withHome((home, t) => {
  const r = run(['--home', home, '--path', join(home, 'notes'), '--path', join(home, 'gateway'), '--json']);
  assert.equal(r.status, 1, r.stderr);
  const j = JSON.parse(r.stdout);
  const rules = new Set(j.findings.map((f) => f.rule));
  for (const id of ['github-oauth', 'github-pat', 'anthropic', 'openai', 'openrouter', 'aws-key-id', 'huggingface', 'npm', 'env-assign', 'db-url', 'stripe-live', 'private-key']) {
    assert.ok(rules.has(id), `missing ${id}; got ${[...rules].join(',')}`);
  }
  assert.equal(j.findings.length, 12, j.findings.map((f) => f.rule).join(','));
  const allFiles = j.findings.flatMap((f) => f.files);
  assert.ok(!allFiles.some((p) => p.includes('clean.jsonl')), 'placeholder file must be clean');
  // values never appear in output
  for (const v of Object.values(t)) assert.ok(!r.stdout.includes(v), 'raw value leaked into output');
}));

test('gh token: counted across agents, marked LIVE because it matches hosts.yml', () => withHome((home, t) => {
  const j = JSON.parse(run(['--home', home, '--json']).stdout);
  const gh = j.findings.find((f) => f.rule === 'github-oauth');
  assert.equal(gh.fingerprint, fingerprint(t.ghOauth));
  assert.equal(gh.occurrences, 3); // twice in the Claude session, once in the Codex sqlite
  assert.deepEqual(gh.agents.sort(), ['Claude Code', 'Codex']);
  assert.equal(gh.live, 'hosts.yml');
  assert.equal(j.findings[0].rule, 'github-oauth', 'live high-severity first');
  const oa = j.findings.find((f) => f.rule === 'openai');
  assert.equal(oa.live, 'auth.json');
  assert.ok(!j.findings.find((f) => f.rule === 'stripe-live'), 'custom paths not scanned unless --path');
}));

test('--redact dry run changes nothing; --redact --yes rewrites and keeps JSONL valid', () => withHome((home, t) => {
  const s1 = join(home, '.claude/projects/-work-api/s1.jsonl');
  const before = readFileSync(s1, 'utf8');
  const mode = statSync(s1).mode;
  const dry = run(['--home', home, '--redact']);
  assert.match(dry.stdout, /dry run/);
  assert.equal(readFileSync(s1, 'utf8'), before);

  const wet = run(['--home', home, '--redact', '--yes']);
  assert.match(wet.stdout, /rewrote \d+ file/);
  const after = readFileSync(s1, 'utf8');
  assert.ok(!after.includes(t.ghOauth));
  assert.ok(after.includes(`[REDACTED:github-oauth:${fingerprint(t.ghOauth)}]`));
  for (const line of after.trim().split('\n')) JSON.parse(line); // still valid JSONL
  assert.equal(statSync(s1).mode, mode);
  // sqlite untouched
  assert.ok(readFileSync(join(home, '.codex/logs_2.sqlite'), 'latin1').includes(t.ghOauth));
  // second scan: only the sqlite copy (and nothing else) remains
  const j = JSON.parse(run(['--home', home, '--json']).stdout);
  assert.deepEqual(j.findings.map((f) => f.rule), ['github-oauth']);
}));

test('active files (modified < 10 min ago) are skipped unless --include-active', () => withHome((home, t) => {
  const s1 = join(home, '.claude/projects/-work-api/s1.jsonl');
  const now = new Date();
  utimesSync(s1, now, now);
  const r = run(['--home', home, '--redact', '--yes']);
  assert.match(r.stdout, /1 active file\(s\) skipped/);
  assert.ok(readFileSync(s1, 'utf8').includes(t.ghOauth));
  run(['--home', home, '--redact', '--yes', '--include-active']);
  assert.ok(!readFileSync(s1, 'utf8').includes(t.ghOauth));
}));

test('--since filters old files', () => withHome((home) => {
  const j = JSON.parse(run(['--home', home, '--since', '4', '--json']).stdout);
  const rules = j.findings.map((f) => f.rule);
  assert.ok(!rules.includes('private-key')); // 20 days old
  assert.ok(!rules.includes('huggingface')); // 30 days old
  assert.ok(rules.includes('github-oauth'));
}));

test('--stdin --redact works as a log filter', () => {
  const t = makeTokens();
  const input = `ts=1 body="token ${t.ghPat}" key=${t.anthropic}\nplain line\n`;
  const r = run(['--stdin', '--redact'], input);
  assert.equal(r.status, 1);
  assert.ok(!r.stdout.includes(t.ghPat) && !r.stdout.includes(t.anthropic));
  assert.match(r.stdout, /\[REDACTED:github-pat:[0-9a-f]{10}\]/);
  assert.ok(r.stdout.endsWith('plain line\n'));
  const clean = run(['--stdin'], 'nothing here\n');
  assert.equal(clean.status, 0);
});

test('JSON-escaped newlines before a token still match; identifiers and placeholders do not', () => {
  const t = makeTokens();
  assert.equal(findSecrets(JSON.stringify(`line1\n${t.ghOauth}`)).length, 1);
  assert.equal(findSecrets(`xghp_${'a'.repeat(36)}`).length, 0);
  assert.equal(findSecrets('API_KEY=your_api_key_here_please').length, 0);
  assert.equal(findSecrets('PASSWORD: settings.database_password_field').length, 0);
  assert.equal(findSecrets('SECRET_KEY=Zq8vN2kLp4XrT7mW9sYb').length, 1);
  // code, not secrets
  assert.equal(findSecrets('  KLAVIYO_API_KEY: organization.KLAVIYO_API_KEY,').length, 0);
  assert.equal(findSecrets('process.env.SIGNING_SECRET = tenantSigningSecret;').length, 0);
  assert.equal(findSecrets('"TWILIO_AUTH_TOKEN=\\nTWILIO_PHONE_NUMBER=+1"').length, 0);
  assert.equal(findSecrets('DATABASE_URL=postgres://app_user:app_user@localhost/db').length, 0);
  assert.equal(findSecrets('xo' + 'xb-1234567890-abcdefghij and AK' + 'IAABCDEFGHIJKLMNOP').length, 0);
  assert.equal(findSecrets('DATABASE_URL=postgres://app:Pg7Hq2xKe9Lm@db.internal/app').length, 1);
  const lin = findSecrets('export LINEAR=' + 'lin' + '_api_' + t.ghPat.slice(4) + 'Q7xZ');
  assert.equal(lin.length, 1);
  assert.equal(lin[0].det.id, 'linear');
});

test('--help and bad flags', () => {
  const h = run(['--help']);
  assert.equal(h.status, 0);
  assert.match(h.stdout, /Usage/);
  assert.equal(run(['--nope']).status, 2);
  assert.equal(run(['--only']).status, 2);
});

test('no sources: friendly message, exit 0', () => {
  const home = mkdtempSync(join(tmpdir(), 'ts-empty-'));
  try {
    const out = execFileSync(process.execPath, [BIN, '--home', home], { encoding: 'utf8' });
    assert.match(out, /No agent transcripts found/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
