# 🔍 AUTO Skills Scanner

[![npm version](https://img.shields.io/npm/v/auto-skills-scanner)](https://www.npmjs.com/package/auto-skills-scanner)
[![npm downloads](https://img.shields.io/npm/dm/auto-skills-scanner)](https://www.npmjs.com/package/auto-skills-scanner)
[![license](https://img.shields.io/npm/l/auto-skills-scanner)](LICENSE)
[![AUTO Scan](https://img.shields.io/badge/AUTO%20Scan-passing-green)](https://github.com/auto-skills-scanner)

**VirusTotal for Agent Skills** — pre-installation supply chain security scanner.

Scan any Agent Skill or MCP server for security threats BEFORE installing. 8 detection categories, 18+ patterns, CVE mapping, zero runtime dependencies.

## Quick Start

```bash
npm install -g auto-skills-scanner

auto-scanner onboard              # First-run setup + AI config
auto-scanner scan ./some-skill/   # Interactive TUI
auto-scanner analyze . --json     # AI-powered summary
```

## Add to Your Repo (GitHub Action)

```yaml
# .github/workflows/scan.yml
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npm install -g auto-skills-scanner
- run: auto-scanner scan .
```

Scans on every PR. Blocks merge if CRITICAL issues found. Auto-comments results.

## Detection Rules

| Rule | Category | Severity |
|------|----------|----------|
| CE-001 | Code Execution | 🔴 CRITICAL |
| DE-001 | Data Exfiltration | 🟠 HIGH |
| AB-001 | Auth Bypass | 🔴 CRITICAL |
| INJ-001 | Injection | 🟠 HIGH |
| CP-001 | Config Poisoning | 🟠 HIGH |
| BA-001 | Behavior Anomaly | 🟡 MEDIUM |
| DC-001 | Dependency Chain | 🟠 HIGH |
| PE-001 | Permission Escalation | 🔴 CRITICAL |

### What each rule detects

- **Code Execution**: `eval()`, `exec()`, `child_process`, `subprocess`, curl-pipe-shell
- **Data Exfiltration**: `process.env`, API key leaks, hardcoded secrets, HTTP to external URLs
- **Auth Bypass**: Hardcoded tokens (OpenAI, GitHub, Slack, AWS, Google), weak auth checks
- **Injection**: Prompt injection, command injection, SQL injection, path traversal
- **Config Poisoning**: Malicious MCP server injection, npx auto-install, HTTP endpoints
- **Behavior Anomaly**: File deletion, SSH/.bashrc modification, persistence mechanisms
- **Dependency Chain**: Suspicious dependency sources, unpinned versions, known CVEs
- **Permission Escalation**: `sudo`, excessive tool permissions, sandbox escapes

## Output Formats

- **Terminal** (default): Color-coded TUI with severity icons, risk score bar, keyboard navigation
- **JSON**: Machine-readable full report with all metadata
- **Markdown**: Formatted report with severity tables and finding details

## TUI Keyboard Controls

| Key | Action |
|-----|--------|
| ↑↓ | Scroll findings |
| PgUp/PgDn | Page scroll |
| 0-4 | Filter: ALL / CRITICAL / HIGH / MEDIUM / LOW |
| a | AI-powered analysis |
| j | Export JSON report |
| m | Export Markdown report |
| q / Esc | Quit |

## AI Integration

Built-in AI analysis using MoMo free API (no account required):

```bash
auto-scanner onboard  # configures AI (default: MiMo free)
```

Press `a` in the TUI for AI executive summary, or run:

```bash
auto-scanner analyze ./some-skill/
```

Compatible with any OpenAI-compatible API endpoint.

## Architecture

```
src/
├── cli.ts              # TUI + onboard + analyze (readline/ANSI native)
├── ansi.ts             # Zero-dependency ANSI color helper
├── types.ts            # Core types (Severity, Finding, ScanResult, etc.)
├── scanner/
│   ├── engine.ts       # Scan orchestrator
│   ├── rules/          # 8 detection rule modules
│   ├── parsers/        # Skill.md + mcp.json parsers
│   └── cve/            # CVE mapping database
├── ai/analyzer.ts      # OpenAI-compatible API client
└── report/formatter.ts # JSON + Markdown output
```

## Roadmap

- [x] 8 core detection rules
- [x] Interactive TUI
- [x] AI-powered analysis
- [x] GitHub Action
- [x] npm package
- [ ] Real CVE feed (NVD API)
- [ ] VS Code extension
- [ ] Claude Code / Cursor / OpenCode plugin

## License

MIT — AUTO Security Tools
