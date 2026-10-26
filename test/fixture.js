// Fake home directory with fake (format-valid, random) credentials scattered through agent transcripts.
// Tokens are generated at runtime so the repo never contains anything that looks like a key.
import { mkdirSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

let seed = 42;
const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';
const gen = (n, cs = ALNUM) => Array.from({ length: n }, () => cs[Math.floor(rnd() * cs.length)]).join('');

export function makeTokens() {
  seed = 42;
  return {
    ghOauth: 'gh' + 'o_' + gen(36),
    ghPat: 'gh' + 'p_' + gen(36),
    anthropic: 'sk-' + 'ant-api03-' + gen(93),
    openai: 'sk-' + 'proj-' + gen(120),
    openrouter: 'sk-' + 'or-v1-' + gen(64, HEX),
    aws: 'AK' + 'IA' + gen(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
    hf: 'h' + 'f_' + gen(34),
    npm: 'np' + 'm_' + gen(36),
    deepseek: 'sk-' + gen(32, HEX),
    dbPass: 'Pg' + gen(18),
    stripe: 'sk' + '_live_' + gen(24),
    privBody: gen(64) + '\n' + gen(64) + '\n' + gen(40),
  };
}

const jl = (...objs) => objs.map((o) => JSON.stringify(o)).join('\n') + '\n';
const DAY = 86400000;

export function makeHome(home) {
  const t = makeTokens();
  const w = (rel, content, ageDays = 3) => {
    const p = join(home, rel);
    mkdirSync(join(p, '..'), { recursive: true });
    writeFileSync(p, content);
    const when = new Date(Date.now() - ageDays * DAY);
    utimesSync(p, when, when);
    return p;
  };
  const pk = ['-----BEGIN OPENSSH PRIVATE', ' KEY-----\n', t.privBody, '\n-----END OPENSSH PRIVATE', ' KEY-----'].join('');

  // Claude Code: the gh token printed by a tool call, then echoed back by the model (the LiteLLM pattern)
  w('.claude/projects/-work-api/s1.jsonl', jl(
    { type: 'user', message: { role: 'user', content: 'why does the release workflow fail?' } },
    { type: 'assistant', message: { content: [{ type: 'tool_use', name: 'Bash', input: { command: 'gh auth status -t' } }] } },
    { type: 'user', message: { content: [{ type: 'tool_result', content: `github.com\n  ✓ Logged in to github.com account dev\n  - Token: ${t.ghOauth}\n  - Token scopes: 'gist', 'read:org', 'repo', 'workflow'` }] } },
    { type: 'assistant', message: { content: [{ type: 'text', text: `You're logged in; the token (${t.ghOauth}) has workflow scope, so the failure is elsewhere.` }] } },
  ), 2);
  w('.claude/projects/-work-api/s2.jsonl', jl(
    { type: 'user', message: { content: [{ type: 'tool_result', content: `OPENAI_API_KEY=${t.openai}\nDEEPSEEK_API_KEY=${t.deepseek}\nDATABASE_URL=postgres://app:${t.dbPass}@db.internal:5432/app` }] } },
  ), 9);
  w('.claude/projects/-work-web/s3.jsonl', jl(
    { type: 'user', message: { content: 'set up the deploy key' } },
    { type: 'user', message: { content: [{ type: 'tool_result', content: pk }] } },
    { type: 'assistant', message: { content: [{ type: 'text', text: 'Use OPENAI_API_KEY=sk-your-key-here in .env (placeholder) and process.env.OPENAI_API_KEY in code.' }] } },
  ), 20);
  w('.claude/history.jsonl', jl({ display: `export ANTHROPIC_API_KEY=${t.anthropic}`, project: '/work/api' }), 1);
  w('.claude/shell-snapshots/snapshot-zsh-1.sh', `export PATH=/usr/bin\nexport HF_TOKEN=${t.hf}\n`, 30);
  w('.claude/projects/-work-clean/clean.jsonl', jl({ type: 'user', message: { content: 'hello, nothing secret here: sk-... and ghp_xxx are placeholders' } }), 1);

  // Codex
  w('.codex/sessions/2026/10/21/rollout-a.jsonl', jl(
    { type: 'response_item', payload: { type: 'function_call_output', output: `{"output":"//registry.npmjs.org/:_authToken=${t.npm}\\n"}` } },
    { type: 'response_item', payload: { type: 'message', content: [{ type: 'output_text', text: `aws_access_key_id = ${t.aws}` }] } },
  ), 1);
  w('.codex/logs_2.sqlite', 'SQLite format 3\u0000' + '\u0000'.repeat(64) + `INSERT ... ${t.ghOauth} ...`, 1);

  // Gemini CLI
  w('.gemini/tmp/abc123/logs.json', JSON.stringify([{ type: 'user', message: `use ${t.openrouter} for the router` }]), 5);

  // A memory folder and a gateway log the user points at with --path
  w('notes/agent-memory/2026-10-20.md', `# Session summary\n- Deployed with Stripe key ${t.stripe}\n`, 2);
  w('gateway/litellm.log', `2026-10-21 10:00:01 response_body="...Token: ${t.ghPat}..."\n`, 1);

  // Credential files that hold the *current* config (only fingerprinted)
  w('.config/gh/hosts.yml', `github.com:\n    oauth_token: ${t.ghOauth}\n    user: dev\n`, 40);
  w('Library/Application Support/gh/hosts.yml', `github.com:\n    oauth_token: ${t.ghOauth}\n    user: dev\n`, 40);
  w('.codex/auth.json', JSON.stringify({ OPENAI_API_KEY: t.openai }), 40);
  return t;
}
