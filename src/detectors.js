// Credential formats that show up in agent transcripts and gateway logs.
// Patterns are assembled from parts so this file does not itself trip secret scanners.

const rx = (...parts) => new RegExp(parts.join(''), 'g');
// Left boundary: not preceded by a token char, OR preceded by a JSON escape like \n \t \r
// (transcripts are JSON, so "...\nghp_..." is common and the char before the token is 'n').
const L = '(?:(?<![A-Za-z0-9_-])|(?<=\\\\[nrt]))';
const B = '(?![A-Za-z0-9_-])';

// severity: 3 = code/infra takeover (publish, cloud, VCS), 2 = paid AI usage / data, 1 = lower impact
export const DETECTORS = [
  // --- version control & package publishing (the LiteLLM entry point was gh OAuth tokens) ---
  { id: 'github-oauth', name: 'GitHub OAuth token (gh CLI)', sev: 3, re: rx(L, 'gh', 'o_[A-Za-z0-9]{36}', B), keep: 4, rotate: 'gh auth refresh / revoke at github.com/settings/applications' },
  { id: 'github-pat', name: 'GitHub personal access token', sev: 3, re: rx(L, 'gh', 'p_[A-Za-z0-9]{36}', B), keep: 4, rotate: 'github.com/settings/tokens' },
  { id: 'github-pat-fine', name: 'GitHub fine-grained PAT', sev: 3, re: rx(L, 'github', '_pat_[A-Za-z0-9_]{60,}', B), keep: 11, rotate: 'github.com/settings/tokens?type=beta' },
  { id: 'github-app', name: 'GitHub app/user-to-server token', sev: 2, re: rx(L, 'gh', '[usr]_[A-Za-z0-9]{36}', B), keep: 4, rotate: 'short-lived; revoke the app installation if still valid' },
  { id: 'gitlab-pat', name: 'GitLab token', sev: 3, re: rx(L, 'gl', 'pat-[A-Za-z0-9_-]{20,}', B), keep: 6, rotate: 'gitlab.com/-/user_settings/personal_access_tokens' },
  { id: 'npm', name: 'npm token', sev: 3, re: rx(L, 'np', 'm_[A-Za-z0-9]{36}', B), keep: 4, rotate: 'npmjs.com → Access Tokens' },
  { id: 'pypi', name: 'PyPI upload token', sev: 3, re: rx(L, 'py', 'pi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}', B), keep: 5, rotate: 'pypi.org/manage/account/token/' },
  // --- cloud ---
  { id: 'aws-key-id', name: 'AWS access key ID', sev: 2, re: rx(L, '(?:AK', 'IA|AS', 'IA)[0-9A-Z]{16}', B), keep: 4, rotate: 'IAM → Security credentials (rotate the key pair)' },
  { id: 'gcp-oauth', name: 'Google OAuth access token', sev: 2, re: rx(L, 'ya', '29\\.[A-Za-z0-9_-]{50,}', B), keep: 5, rotate: 'short-lived (~1h); revoke the refresh token at myaccount.google.com/permissions' },
  // whole block (works for JSON transcripts with \n escapes and for plain multi-line files)
  { id: 'private-key', name: 'Private key block', sev: 3, re: rx('-----BEGIN ((?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?)PRIVATE', ' KEY-----[\\s\\S]{40,12000}?-----END \\1PRIVATE', ' KEY-----'), keep: 0, rotate: 'regenerate the key pair and remove the old public key everywhere' },
  // --- AI providers ---
  { id: 'anthropic', name: 'Anthropic API key', sev: 2, re: rx(L, 'sk-', 'ant-api\\d\\d-[A-Za-z0-9_-]{60,}', B), keep: 14, rotate: 'console.anthropic.com/settings/keys' },
  { id: 'anthropic-admin', name: 'Anthropic admin key', sev: 3, re: rx(L, 'sk-', 'ant-admin\\d\\d-[A-Za-z0-9_-]{60,}', B), keep: 16, rotate: 'console.anthropic.com/settings/admin-keys' },
  { id: 'anthropic-oauth', name: 'Claude subscription OAuth token', sev: 2, re: rx(L, 'sk-', 'ant-o(?:at|rt)\\d\\d-[A-Za-z0-9_-]{40,}', B), keep: 14, rotate: 'log out of Claude Code (`/logout`) and sign in again' },
  { id: 'openai', name: 'OpenAI API key', sev: 2, re: rx(L, 'sk-', '(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}', B), keep: 8, rotate: 'platform.openai.com/api-keys' },
  { id: 'openai-legacy', name: 'OpenAI API key (legacy)', sev: 2, re: rx(L, 'sk-', '[A-Za-z0-9]{20}T3Blbk', 'FJ[A-Za-z0-9]{20}', B), keep: 3, rotate: 'platform.openai.com/api-keys' },
  { id: 'openrouter', name: 'OpenRouter key', sev: 2, re: rx(L, 'sk-', 'or-v1-[a-f0-9]{64}', B), keep: 9, rotate: 'openrouter.ai/settings/keys' },
  { id: 'google-api', name: 'Google API key (Gemini / AI Studio)', sev: 2, re: rx(L, 'AI', 'za[0-9A-Za-z_-]{35}', B), keep: 4, rotate: 'aistudio.google.com/app/apikey or GCP credentials page' },
  { id: 'groq', name: 'Groq key', sev: 2, re: rx(L, 'gs', 'k_[A-Za-z0-9]{48,}', B), keep: 4, rotate: 'console.groq.com/keys' },
  { id: 'xai', name: 'xAI key', sev: 2, re: rx(L, 'xa', 'i-[A-Za-z0-9]{70,}', B), keep: 4, rotate: 'console.x.ai' },
  { id: 'huggingface', name: 'Hugging Face token', sev: 2, re: rx(L, 'h', 'f_[A-Za-z0-9]{34,}', B), keep: 3, rotate: 'huggingface.co/settings/tokens' },
  { id: 'replicate', name: 'Replicate token', sev: 2, re: rx(L, 'r', '8_[A-Za-z0-9]{37,}', B), keep: 3, rotate: 'replicate.com/account/api-tokens' },
  { id: 'perplexity', name: 'Perplexity key', sev: 2, re: rx(L, 'pp', 'lx-[A-Za-z0-9]{40,}', B), keep: 5, rotate: 'perplexity.ai/settings/api' },
  { id: 'linear', name: 'Linear API key', sev: 2, re: rx(L, 'lin', '_api_[A-Za-z0-9]{40}', B), keep: 8, rotate: 'linear.app → Settings → Security & access → API keys' },
  // --- payments / messaging ---
  { id: 'stripe-live', name: 'Stripe live secret key', sev: 3, re: rx(L, '(?:sk|rk)', '_live_[A-Za-z0-9]{20,}', B), keep: 8, rotate: 'dashboard.stripe.com/apikeys (roll key)' },
  { id: 'slack', name: 'Slack token', sev: 2, re: rx(L, 'xo', 'x[baprs]-[A-Za-z0-9-]{20,}', B), keep: 5, rotate: 'api.slack.com/apps → reinstall / revoke' },
  // --- generic: known env-var names assigned a value (DeepSeek, Mistral, DB URLs, ...) ---
  {
    id: 'env-assign', name: 'Secret-named variable with a value', sev: 1, generic: true,
    // the value may sit behind an escaped quote (\"...\") but never right after a bare backslash (\n = empty value)
    re: rx('(?:(?<![A-Za-z0-9_])|(?<=\\\\[nrt]))((?:[A-Z][A-Z0-9_]*_)?(?:API_KEY|SECRET_KEY|ACCESS_KEY|SECRET|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|PASSWORD|PASSWD)|aws_secret_access_key', ')((?:\\\\?["\'])?[ \\t]*[=:][ \\t]*(?:\\\\?["\'])?)([A-Za-z0-9_\\-./+]{16,})'),
    keep: 0, rotate: 'rotate at the issuing service',
  },
  {
    id: 'db-url', name: 'Database URL with password', sev: 2, generic: true,
    re: rx('((?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|rediss|amqp)://[^:/\\s"\'@]+:)', '([^@\\s"\'/\\\\]{6,})(@)'),
    keep: 0, rotate: 'change the database user password', urlForm: true,
  },
];

// Generic hits that are really code: `KEY: org.KLAVIYO_API_KEY`, `SECRET = signingSecret`, `postgres://app:app@`.
export function rejectGeneric(det, m, value) {
  if (det.id === 'db-url') {
    const user = m[1].replace(/^.*:\/\//, '').replace(/:$/, '');
    return value === user;
  }
  if (det.id === 'env-assign') {
    const quoted = /["']/.test(m[2]);
    if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value)) return true; // dotted property path
    if (!quoted && /^[A-Za-z_$][A-Za-z_$]*$/.test(value) && /[a-z][A-Z]/.test(value)) return true; // bare camelCase identifier
    if (/^(?:https?|file):\/\//.test(value) || value.startsWith('/') || value.startsWith('./')) return true; // URL / path
  }
  return false;
}

// For generic rules the secret is a capture group, not the whole match.
export function secretOf(det, m) {
  if (det.id === 'env-assign') return { value: m[3], start: m.index + m[1].length + m[2].length };
  if (det.id === 'db-url') return { value: m[2], start: m.index + m[1].length };
  return { value: m[0], start: m.index };
}

// generic=false: the value already has a distinctive prefix, so only reject clearly hand-typed fillers
// (word fillers must be delimited, so a random 120-char key that happens to contain "your" still counts).
export function isPlaceholder(v, generic = true) {
  const s = String(v);
  if (s.length < 12) return true;
  if (generic && /example|placeholder|changeme|replace|redacted|dummy|your[_-]?|xxxx|\*\*\*|<|>|\$\{|^\$|^env[:.]|^process\.|^os\.environ|test[_-]?key|fake/i.test(s)) return true;
  if (!generic && /(?:^|[-_])(?:your|example|placeholder|changeme|replace|redacted|dummy|test|fake|sample|xxxx\w*)(?:[-_]|$)|\*\*\*|\.\.\./i.test(s)) return true;
  if (/^(.)\1+$/.test(s)) return true;
  // hand-typed test values: long ascending runs (abcdefgh, 12345678, ABCDEFGH) or 6+ repeated chars
  if (/abcdefgh|bcdefghi|12345678|23456789|ABCDEFGH|BCDEFGHI|(.)\1{5}/i.test(s)) return true;
  // all-lowercase words with underscores/dots/dashes (e.g. "settings.api_key_value", "schema-migrator") are identifiers
  if (/^[a-z_.-]+$/.test(s)) return true;
  // ALL_CAPS identifiers (the next variable name after an empty assignment)
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(s)) return true;
  return false;
}

// Generic env-assign hits need some entropy, otherwise "PASSWORD=correcthorsebattery" style prose dominates.
export function looksRandom(v) {
  const s = String(v);
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(s)).length;
  if (classes < 2) return false;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  for (const k in freq) { const p = freq[k] / s.length; h -= p * Math.log2(p); }
  return h >= 3.3;
}

export function mask(value, keep) {
  const s = String(value);
  if (s.startsWith('-----BEGIN')) return `${(s.match(/^-----BEGIN ([A-Z]+ )?/)[1] || '').trim() || 'PKCS8'} key block, ${s.length} chars`;
  const head = keep > 0 ? s.slice(0, Math.min(keep, s.length - 8)) : '';
  return `${head}…${s.slice(-4)}`;
}

// Cheap prefilter: skip lines that cannot contain any detector.
export const PREFILTER = new RegExp([
  'gh[opusr]_', 'github_pat_', 'glpat-', 'npm_', 'pypi-', 'AKIA', 'ASIA', 'ya29\\.', 'PRIVATE KEY', 'sk-', 'AIza', 'gsk_', 'xai-',
  'hf_', 'r8_', 'pplx-', 'lin_api_', '_live_', 'xox', '_KEY', 'SECRET', 'TOKEN', 'PASSW', '://',
].join('|'));
