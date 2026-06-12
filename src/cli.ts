#!/usr/bin/env node
// AUTO Skills Scanner CLI — Terminal-native interactive TUI
import { scan } from './scanner/engine';
import { formatJson, formatMarkdown } from './report/formatter';
import { ScanResult, Finding, Severity } from './types';
import { generateAISummary, analyzeFinding, checkApiHealth, AiConfig, DEFAULT_AI_CONFIG } from './ai/analyzer';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as readline from 'readline';
import { ansi, color } from './ansi';

const VERSION = '0.1.0';

const CSI = '\x1b[';
const cursorHide = CSI + '?25l';
const cursorShow = CSI + '?25h';
const clearScreen = CSI + '2J' + CSI + 'H';

// Severity display
type SevStyle = { code: string; bg: string; icon: string };
const SEV: Record<Severity, SevStyle> = {
  CRITICAL: { code: ansi.red, bg: ansi.bgRed, icon: '!' },
  HIGH:     { code: ansi.hex('#FF8800'), bg: '', icon: '!' },
  MEDIUM:   { code: ansi.yellow, bg: '', icon: '!' },
  LOW:      { code: ansi.blue, bg: '', icon: 'i' },
  INFO:     { code: ansi.gray, bg: '', icon: 'i' },
};

const CAT: Record<string, string> = {
  'code-execution': 'CodeExec', 'data-exfiltration': 'DataExfil',
  'auth-bypass': 'AuthBypass', 'injection': 'Injection',
  'config-poisoning': 'ConfigPoison', 'behavior-anomaly': 'Behavior',
  'dependency-chain': 'Deps', 'permission-escalation': 'PrivEscal',
};

// ── Render ──
function render(result: ScanResult | null, error: string | null, filter: Severity | 'ALL', scroll: number, targetPath: string): string {
  let out = clearScreen + cursorHide;

  // Header
  out += color('  AUTO Skills Scanner', ansi.hex('#4488FF') + ansi.bold) + '  ' + color('v' + VERSION, ansi.dim) + '\n';
  out += color('  ' + '-'.repeat(process.stdout.columns ? Math.min(process.stdout.columns - 2, 60) : 58), ansi.dim) + '\n\n';

  if (!result) {
    if (error) {
      out += color('  ERROR: ' + error, ansi.red) + '\n';
    } else {
      out += '  Scanning ' + color(path.basename(targetPath), ansi.hex('#FFCC00')) + '...\n\n';
      out += color('  CE DE AB INJ CP BA DC PE', ansi.dim) + '\n';
    }
    return out;
  }

  const { meta, summary } = result;
  out += color('  ' + path.basename(targetPath) + '  -  ' + meta.totalFiles + ' files  -  ' + meta.durationMs + 'ms', ansi.dim) + '\n\n';

  // Risk
  const riskScore = summary.riskScore;
  const riskColor = riskScore >= 70 ? ansi.red : riskScore >= 40 ? ansi.hex('#FF8800') : ansi.green;
  const barW = 28;
  const filled = Math.round((riskScore / 100) * barW);
  const bar = '[' + '='.repeat(Math.max(0, filled)) + '-'.repeat(Math.max(0, barW - filled)) + ']';
  out += color('  Risk: ', ansi.bold) + color(bar + ' ' + riskScore + '/100', riskColor) + '\n';

  const safe = summary.safeToInstall;
  out += color('  Status: ', ansi.bold) + (safe ? color('SAFE to install', ansi.green) : color('UNSAFE - do not install', ansi.red)) + '\n';
  out += color('  Findings: ', ansi.bold) + color('' + summary.totalFindings, ansi.hex('#FFCC00')) + '  ';

  for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]) {
    const c = summary.bySeverity[s];
    if (c > 0) out += color(s + ':' + c + ' ', SEV[s].code);
  }
  out += '\n\n';

  // Filter bar
  const filters = [
    { k: 'ALL', l: 'ALL', c: ansi.white }, { k: 'CRITICAL', l: 'CRIT', c: ansi.red },
    { k: 'HIGH', l: 'HIGH', c: ansi.hex('#FF8800') }, { k: 'MEDIUM', l: 'MED', c: ansi.yellow },
    { k: 'LOW', l: 'LOW', c: ansi.blue },
  ];
  out += '  ';
  for (const f of filters) {
    out += filter === f.k
      ? color(' ' + f.l + ' ', ansi.bgWhite + ansi.black)
      : color(' ' + f.l + ' ', f.c);
    out += ' ';
  }
  out += color(' [0-4]filter  [a]AI  [j]JSON  [m]MD  [q]quit', ansi.dim) + '\n';
  out += color('  ' + '-'.repeat(process.stdout.columns ? Math.min(process.stdout.columns - 2, 60) : 58), ansi.dim) + '\n';

  // Findings
  const filtered = filter === 'ALL' ? result.findings : result.findings.filter(f => f.severity === filter);
  const visStart = Math.max(0, Math.min(scroll, filtered.length - 1));
  const visEnd = Math.min(filtered.length, visStart + Math.max(4, (process.stdout.rows || 30) - 14));
  const items = filtered.slice(visStart, visEnd);

  if (items.length === 0) {
    out += '\n  ' + color('No findings for this filter', ansi.green) + '\n';
  } else {
    for (let i = 0; i < items.length; i++) {
      const f = items[i];
      const idx = visStart + i + 1;
      const s = SEV[f.severity];
      const cat = CAT[f.category] || f.category;
      const file = f.file + (f.line ? ':' + f.line : '');

      out += '  ' + color('[' + idx + ']', s.code) + ' ' + color(f.ruleName, ansi.bold);
      out += color(' - ' + cat + ' - ' + file, ansi.dim) + '\n';
      out += '    ' + color(f.description, ansi.dim) + '\n';
      if (f.evidence) {
        const ev = f.evidence.length > 60 ? f.evidence.slice(0, 57) + '...' : f.evidence;
        out += '    ' + color('| ' + ev, ansi.dim) + '\n';
      }
      out += '    ' + color('> ' + f.remediation, ansi.green) + '\n\n';
    }
  }

  const scrollInfo = (visStart + 1) + '-' + visEnd + ' of ' + filtered.length +
    (filter !== 'ALL' ? ' (filtered from ' + result.findings.length + ')' : '');
  out += color('  ' + scrollInfo + '  [arrows/pgup/pgdn]scroll', ansi.dim) + '\n';

  return out;
}

// ── TUI ──
async function runTui(targetPath: string): Promise<void> {
  let result: ScanResult | null = null;
  let error: string | null = null;
  let filter: Severity | 'ALL' = 'ALL';
  let scroll = 0;

  const rl = readline.createInterface({ input: process.stdin, escapeCodeTimeout: 50 });
  readline.emitKeypressEvents(process.stdin);
  if (process.stdin.isTTY) process.stdin.setRawMode(true);

  const redraw = () => {
    process.stdout.write(render(result, error, filter, scroll, targetPath));
  };

  redraw();

  const onKey = (_s: string, key: readline.Key) => {
    if (!result) return;
    const filtered = filter === 'ALL' ? result.findings : result.findings.filter(f => f.severity === filter);

    if (key.name === 'up') scroll = Math.max(0, scroll - 1);
    else if (key.name === 'down') scroll = Math.min(filtered.length - 1, scroll + 1);
    else if (key.name === 'pageup') scroll = Math.max(0, scroll - 10);
    else if (key.name === 'pagedown') scroll = Math.min(filtered.length - 1, scroll + 10);
    else if (key.name === 'home') scroll = 0;
    else if (key.name === 'end') scroll = Math.max(0, filtered.length - 1);
    else if (key.sequence === '0') { filter = 'ALL'; scroll = 0; }
    else if (key.sequence === '1') { filter = Severity.CRITICAL; scroll = 0; }
    else if (key.sequence === '2') { filter = Severity.HIGH; scroll = 0; }
    else if (key.sequence === '3') { filter = Severity.MEDIUM; scroll = 0; }
    else if (key.sequence === '4') { filter = Severity.LOW; scroll = 0; }
    else if (key.sequence === 'a') runAiAnalysis(result, rl);
    else if (key.sequence === 'j') exportAndExit(result, 'json', rl);
    else if (key.sequence === 'm') exportAndExit(result, 'markdown', rl);
    else if (key.name === 'escape' || key.sequence === 'q') done(result, rl);
    redraw();
  };

  process.stdin.on('keypress', onKey);

  try {
    result = await scan(targetPath);
    redraw();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
    redraw();
    process.stdout.write(cursorShow);
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
    rl.close();
    process.exit(2);
  }
}

async function runAiAnalysis(result: ScanResult, rl: readline.Interface): Promise<void> {
  process.stdout.write(clearScreen + cursorShow);
  if (process.stdin.isTTY) process.stdin.setRawMode(false);

  console.log(color('\n  AI Analysis', ansi.hex('#4488FF') + ansi.bold));
  const config = loadConfig();
  if (!config.enabled) {
    console.log(color('  AI disabled. Run `auto-scanner onboard` to set up.', ansi.yellow));
  } else {
    console.log(color('  Analyzing with ' + config.model + '...\n', ansi.dim));
    const summary = await generateAISummary(config, result);
    if (summary) {
      console.log('  ' + summary.split('\n').join('\n  '));
      console.log(color('\n  [any key] Back to results', ansi.dim));
    } else {
      console.log(color('  AI unavailable.', ansi.yellow));
    }
  }

  // Wait for any key to go back
  await new Promise<void>(resolve => {
    const onKey = () => { process.stdin.removeListener('keypress', onKey); resolve(); };
    process.stdin.on('keypress', onKey);
  });

  // Back to TUI
  if (process.stdin.isTTY) process.stdin.setRawMode(true);
  process.stdout.write(render(result, null, 'ALL', 0, ''));
}

function exportAndExit(result: ScanResult, fmt: string, rl: readline.Interface): void {
  const outPath = path.join(process.cwd(), fmt === 'json' ? 'auto-scanner-report.json' : 'auto-scanner-report.md');
  fs.writeFileSync(outPath, fmt === 'json' ? formatJson(result) : formatMarkdown(result));
  process.stdout.write(clearScreen + cursorShow);
  console.log(color('Report saved: ' + outPath, ansi.green));
  done(result, rl);
}

function done(result: ScanResult, rl: readline.Interface): void {
  process.stdout.write(cursorShow);
  if (process.stdin.isTTY) process.stdin.setRawMode(false);
  rl.close();
  process.exit(result.summary.bySeverity.CRITICAL > 0 ? 1 : 0);
}

// ── Config ──
const CONFIG_PATH = path.join(os.homedir(), '.auto-scanner.json');

function loadConfig(): AiConfig {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return { ...DEFAULT_AI_CONFIG, ...JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8')) };
    }
  } catch { /* ignore */ }
  return { ...DEFAULT_AI_CONFIG };
}

function saveConfig(config: AiConfig): void {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// ── Onboard ──
async function runOnboard(): Promise<void> {
  console.log(clearScreen + color('\n  AUTO Skills Scanner', ansi.hex('#4488FF') + ansi.bold) + color(' v' + VERSION, ansi.dim));
  console.log(color('  VirusTotal for Agent Skills', ansi.dim) + '\n');

  console.log(color('  Welcome!', ansi.bold));
  console.log('  AUTO Scanner checks Agent Skills and MCP servers for security');
  console.log('  threats BEFORE you install them.\n');
  console.log('  8 detection categories:');
  console.log('    CE Code Execution      CP Config Poisoning');
  console.log('    DE Data Exfiltration    BA Behavior Anomaly');
  console.log('    AB Auth Bypass          DC Dependency Chain');
  console.log('    INJ Injection           PE Permission Escalation\n');

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q: string): Promise<string> => new Promise(r => rl.question(q, r));

  // AI config
  console.log(color('  AI Analysis (optional)', ansi.bold));
  console.log('  Uses MiMo free API by default for AI-assisted analysis.');
  console.log('  No account needed - anonymous access included.\n');

  const useAi = await ask(color('  Enable AI analysis? [Y/n]: ', ansi.hex('#FFCC00')));
  const config = loadConfig();

  if (useAi.toLowerCase() !== 'n') {
    const customApi = await ask(color('  Use custom API? Press enter for MiMo free: ', ansi.dim));
    if (customApi.trim()) {
      config.baseUrl = customApi.trim();
      const key = await ask(color('  API Key: ', ansi.dim));
      if (key.trim()) config.apiKey = key.trim();
      const model = await ask(color('  Model [' + config.model + ']: ', ansi.dim));
      if (model.trim()) config.model = model.trim();
    }
    config.enabled = true;

    // Test API
    console.log('\n  Testing API connection...');
    const health = await checkApiHealth(config);
    if (health.ok) {
      console.log(color('  API connected! Model: ' + health.model, ansi.green));
    } else {
      console.log(color('  API test failed: ' + (health.error || 'unknown'), ansi.yellow));
      console.log(color('  AI features will be disabled. You can reconfigure later.', ansi.dim));
      config.enabled = false;
    }
  } else {
    config.enabled = false;
  }

  saveConfig(config);
  console.log(color('\n  Config saved to ' + CONFIG_PATH, ansi.dim));

  // Offer demo scan
  console.log('\n' + color('  Ready to try your first scan?', ansi.bold));
  const demoPath = await ask(color('  Path to scan (enter to skip): ', ansi.hex('#FFCC00')));

  rl.close();

  if (demoPath.trim()) {
    console.log(clearScreen);
    // Use the scan command flow
    const result = await scan(demoPath.trim());
    const { summary } = result;

    console.log(color('\n  Scan complete!', ansi.green));
    const riskCode = summary.riskScore >= 70 ? ansi.red : summary.riskScore >= 40 ? ansi.hex('#FF8800') : ansi.green;
    console.log('  Risk Score: ' + color('' + summary.riskScore + '/100', riskCode));
    console.log('  Findings: ' + summary.totalFindings);
    for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]) {
      if (summary.bySeverity[s] > 0) console.log('    ' + s + ': ' + summary.bySeverity[s]);
    }
    console.log('  Safe to Install: ' + (summary.safeToInstall ? color('YES', ansi.green) : color('NO', ansi.red)));

    if (config.enabled && summary.totalFindings > 0) {
      console.log('\n  ' + color('AI Analysis:', ansi.bold));
      const aiSummary = await generateAISummary(config, result);
      if (aiSummary) {
        console.log('  ' + aiSummary.split('\n').join('\n  '));
      } else {
        console.log(color('  (AI unavailable)', ansi.dim));
      }
    }

    console.log('\n  Full report: auto-scanner scan ' + demoPath.trim());
    console.log('  Export JSON:  auto-scanner scan ' + demoPath.trim() + ' --json');
    console.log('  See you next time!\n');
  } else {
    console.log('\n  Try it anytime: ' + color('auto-scanner scan <path>', ansi.hex('#FFCC00')) + '\n');
  }
}

// ── Entry ──
void (async function main() {
const args = process.argv.slice(2);

// Onboard command
if (args[0] === 'onboard') {
  runOnboard().then(() => process.exit(0)).catch(e => { console.error('Onboard failed:', e); process.exit(1); });
  return; // TS doesn't know, but prevent fallthrough
}

// Analyze command: scan + AI summary
if (args[0] === 'analyze') {
  const target = args[1];
  if (!target) { console.error('Usage: auto-scanner analyze <path>'); process.exit(1); }
  (async () => {
    const config = loadConfig();
    const result = await scan(target);
    console.log(color('\n  AUTO Scanner — AI Analysis', ansi.hex('#4488FF') + ansi.bold) + '\n');
    if (config.enabled) {
      const summary = await generateAISummary(config, result);
      if (summary) {
        console.log('  ' + summary.split('\n').join('\n  '));
      } else {
        console.log(color('  AI unavailable. Raw findings:', ansi.dim));
        console.log('  ' + result.summary.totalFindings + ' findings, Risk: ' + result.summary.riskScore + '/100');
      }
    } else {
      console.log(color('  AI disabled. Run `auto-scanner onboard` to configure.', ansi.dim));
    }
    process.exit(result.summary.bySeverity.CRITICAL > 0 ? 1 : 0);
  })().catch(e => { console.error('Analyze failed:', e); process.exit(2); });
  return;
}

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
  ${color('AUTO Skills Scanner', ansi.hex('#4488FF') + ansi.bold)} ${color('v' + VERSION, ansi.dim)}
  VirusTotal for Agent Skills - supply chain security scanning

  ${color('USAGE', ansi.bold)}
    auto-scanner onboard              First-run setup wizard
    auto-scanner scan <path>          Interactive TUI
    auto-scanner analyze <path>       Scan + AI-powered summary
    auto-scanner scan <path> --json   JSON to stdout
    auto-scanner scan <path> --md     Markdown to stdout

  ${color('TUI KEYS', ansi.bold)}
    arrows    Scroll findings        home/end  Jump
    pgup/dn   Page scroll            0-4       Filter severity
    a         AI analysis            j         Export JSON
    m         Export Markdown        q/esc     Quit

  ${color('CATEGORIES', ansi.bold)}
    CE Code Exec    CP Config Poison    DE Data Exfil   BA Behavior
    AB Auth Bypass  DC Dependencies     INJ Injection   PE Priv Escal
`);
  process.exit(0);
}

let scanPath = '';
let outFmt: string | undefined;

for (const a of args) {
  if (a === 'scan') continue;
  if (a === '--json' || a === '-j') { outFmt = 'json'; continue; }
  if (a === '--md' || a === '--markdown') { outFmt = 'markdown'; continue; }
  if (a.startsWith('-')) continue;
  if (!scanPath) scanPath = a;
}

if (!scanPath) { console.error('Error: scan path required'); process.exit(1); }

if (outFmt) {
  (async () => {
    try {
      const result = await scan(scanPath);
      console.log(outFmt === 'json' ? formatJson(result) : formatMarkdown(result));
      process.exit(result.summary.bySeverity.CRITICAL > 0 ? 1 : 0);
    } catch (e) {
      console.error('Scan failed:', e instanceof Error ? e.message : String(e));
      process.exit(2);
    }
  })();
} else {
  runTui(scanPath).catch(e => { console.error('Fatal:', e); process.exit(2); });
}
})();
