// Where agent CLIs keep transcripts, logs and memories (not their credential files:
// those are *supposed* to hold secrets; this tool looks for secrets that leaked into history).
import { join } from 'node:path';

export function defaultSources(home, platform = process.platform) {
  const appSupport = platform === 'darwin' ? join(home, 'Library', 'Application Support')
    : platform === 'win32' ? join(home, 'AppData', 'Roaming') : join(home, '.config');
  const vsGlobal = (app) => join(appSupport, app, 'User', 'globalStorage');
  return [
    { agent: 'Claude Code', kind: 'sessions', path: join(home, '.claude', 'projects') },
    { agent: 'Claude Code', kind: 'prompt history', path: join(home, '.claude', 'history.jsonl') },
    { agent: 'Claude Code', kind: 'paste cache', path: join(home, '.claude', 'paste-cache') },
    { agent: 'Claude Code', kind: 'file history', path: join(home, '.claude', 'file-history') },
    { agent: 'Claude Code', kind: 'shell snapshots', path: join(home, '.claude', 'shell-snapshots') },
    { agent: 'Claude Code', kind: 'debug logs', path: join(home, '.claude', 'debug') },
    { agent: 'Claude Code', kind: 'todos/plans', path: join(home, '.claude', 'plans') },
    { agent: 'Codex', kind: 'sessions', path: join(home, '.codex', 'sessions') },
    { agent: 'Codex', kind: 'archived sessions', path: join(home, '.codex', 'archived_sessions') },
    { agent: 'Codex', kind: 'prompt history', path: join(home, '.codex', 'history.jsonl') },
    { agent: 'Codex', kind: 'memories', path: join(home, '.codex', 'memories') },
    { agent: 'Codex', kind: 'shell snapshots', path: join(home, '.codex', 'shell_snapshots') },
    { agent: 'Codex', kind: 'logs (sqlite)', path: join(home, '.codex'), sqliteOnly: true },
    { agent: 'Gemini CLI', kind: 'sessions', path: join(home, '.gemini', 'tmp') },
    { agent: 'Gemini CLI', kind: 'history', path: join(home, '.gemini', 'history') },
    { agent: 'OpenCode', kind: 'sessions', path: join(home, '.local', 'share', 'opencode', 'storage') },
    { agent: 'OpenCode', kind: 'logs', path: join(home, '.local', 'share', 'opencode', 'log') },
    { agent: 'Cline', kind: 'tasks', path: join(vsGlobal('Code'), 'saoudrizwan.claude-dev', 'tasks') },
    { agent: 'Cline (Cursor)', kind: 'tasks', path: join(vsGlobal('Cursor'), 'saoudrizwan.claude-dev', 'tasks') },
    { agent: 'Roo Code', kind: 'tasks', path: join(vsGlobal('Code'), 'rooveterinaryinc.roo-cline', 'tasks') },
    { agent: 'Aider', kind: 'chat history', path: join(home, '.aider.chat.history.md') },
    { agent: 'Aider', kind: 'input history', path: join(home, '.aider.input.history') },
  ];
}

// Credential files that legitimately hold the *current* credentials. Read only to fingerprint,
// so findings can say "this leaked token is still the one configured on this machine".
export function liveCredentialFiles(home, platform = process.platform) {
  const cfg = platform === 'darwin' ? join(home, 'Library', 'Application Support') : join(home, '.config');
  return [
    join(home, '.claude', '.credentials.json'),
    join(home, '.codex', 'auth.json'),
    join(home, '.gemini', 'oauth_creds.json'),
    join(home, '.gemini', '.env'),
    join(home, '.cursor', 'mcp.json'),
    join(home, '.config', 'gh', 'hosts.yml'),
    join(cfg, 'gh', 'hosts.yml'),
    join(home, '.npmrc'),
    join(home, '.pypirc'),
    join(home, '.aws', 'credentials'),
    join(home, '.netrc'),
    join(home, '.git-credentials'),
    join(home, '.local', 'share', 'opencode', 'auth.json'),
    join(home, '.config', 'opencode', 'opencode.json'),
    join(home, '.zshrc'), join(home, '.bashrc'), join(home, '.bash_profile'), join(home, '.profile'), join(home, '.zprofile'),
    join(home, '.config', 'fish', 'config.fish'),
    join(home, '.env'),
  ];
}
