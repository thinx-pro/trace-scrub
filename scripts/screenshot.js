// Build a fake home with fake tokens in agent transcripts, run the CLI with colour, write assets/demo.html.
// Usage: node scripts/screenshot.js  (then screenshot assets/demo.html with headless Chrome)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeHome } from '../test/fixture.js';

const home = mkdtempSync(join(tmpdir(), 'ts-demo-'));
makeHome(home);
const bin = fileURLToPath(new URL('../bin/trace-scrub.js', import.meta.url));
let out;
try {
  execFileSync(process.execPath, [bin, '--home', home, '--path', join(home, 'gateway')], { env: { PATH: process.env.PATH, FORCE_COLOR: '1' }, encoding: 'utf8' });
} catch (e) { out = e.stdout; } // exit 1 = secrets found
rmSync(home, { recursive: true, force: true });
out = out.split(home).join('~');

const COLORS = { 31: '#ff6b6b', 32: '#5af78e', 33: '#f3f99d', 35: '#ff6ac1', 36: '#9aedfe' };
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
let html = '';
let open = 0;
for (const part of out.split(/(\x1b\[[0-9;]*m)/)) {
  const m = part.match(/^\x1b\[([0-9;]*)m$/);
  if (!m) { html += esc(part); continue; }
  const code = Number(m[1]);
  if (code === 0) { html += '</span>'.repeat(open); open = 0; continue; }
  html += `<span style="${code === 1 ? 'font-weight:700' : code === 2 ? 'opacity:.55' : COLORS[code] ? 'color:' + COLORS[code] : ''}">`;
  open++;
}
const page = `<!doctype html><meta charset="utf-8"><style>
body{margin:0;background:#0d1117}
.win{margin:24px;border-radius:10px;background:#161b22;box-shadow:0 8px 30px rgba(0,0,0,.5);overflow:hidden;width:max-content}
.bar{height:30px;background:#21262d;display:flex;align-items:center;padding-left:12px;gap:8px}
.bar i{width:12px;height:12px;border-radius:50%;display:inline-block}
pre{margin:0;padding:16px 20px 20px;color:#e6edf3;font:13px/1.5 "SF Mono",Menlo,Consolas,monospace;white-space:pre}
</style><div class="win"><div class="bar"><i style="background:#ff5f56"></i><i style="background:#ffbd2e"></i><i style="background:#27c93f"></i></div><pre><span style="color:#8b949e">$ npx github:thinx-pro/trace-scrub --path ~/gateway      # demo home with fake tokens</span>
${html}</pre></div>`;
writeFileSync(fileURLToPath(new URL('../assets/demo.html', import.meta.url)), page);
console.log('ok');
