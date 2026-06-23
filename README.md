# 🔒 AUTO Skills Scanner

**The VirusTotal for Agent Skills** — scan BEFORE you install.

[![npm version](https://img.shields.io/npm/v/auto-skills-scanner)](https://www.npmjs.com/package/auto-skills-scanner)
[![npm downloads](https://img.shields.io/npm/dm/auto-skills-scanner)](https://www.npmjs.com/package/auto-skills-scanner)
[![license](https://img.shields.io/npm/l/auto-skills-scanner)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-green)](https://nodejs.org)

> **Don't install a stranger's AI Skill without scanning it first.**

## Why This Matters

The Agent ecosystem is the new npm — and like npm in 2016, there's no security.

- **1,184 malicious Skills** discovered in 2026 ([ClawHavoc attack](https://example.com))
- **26% of Agent code** has security issues ([Cisco report](https://example.com))
- **Zero security tools** existed for Agent Skills — until now

Anyone can publish a Skill that reads your files, steals your API keys, or runs malicious code. AUTO Scanner detects these threats **before** you install.

## Quick Start

```bash
# Scan a skill or MCP server
npx auto-skills-scanner scan ./some-skill/

# Or install globally
npm install -g auto-skills-scanner
auto-scanner scan .
```

## What It Detects

| Category | Rule | Severity | Examples |
|----------|------|----------|----------|
| Code Execution | CE-001 | 🔴 CRITICAL | `eval()`, `exec()`, `child_process` |
| Data Exfiltration | DE-001 | 🟠 HIGH | `process.env`, API key leaks, hardcoded secrets |
| Auth Bypass | AB-001 | 🔴 CRITICAL | Hardcoded tokens (OpenAI, GitHub, AWS) |
| Injection | INJ-001 | 🟠 HIGH | Prompt injection, command injection, path traversal |
| Config Poisoning | CP-001 | 🟠 HIGH | Malicious MCP server injection, npx auto-install |
| Behavior Anomaly | BA-001 | 🟡 MEDIUM | File deletion, SSH/.bashrc modification |
| Dependency Chain | DC-001 | 🟠 HIGH | Known CVEs, suspicious sources |
| Permission Escalation | PE-001 | 🔴 CRITICAL | `sudo`, sandbox escapes, excessive permissions |

**18 detection rules** based on real CVE/attack events. Each rule has a CWE mapping.

## Example Output

```
🔍 AUTO Skills Scanner v0.2.0

Target: ./malicious-skill/
Duration: 14ms
Files: 2

Findings:
  🔴 CRITICAL (3)
    CE-001: Command execution without sandboxing
    PE-001: child_process enables command execution
    PE-001: process.exit() could escape sandbox

  🟠 HIGH (3)
    DE-001: Hardcoded API key in source code
    DE-001: Reading files - could exfiltrate data
    DC-001: Vulnerable lodash (CVE-2021-23337)

  🟡 MEDIUM (1)
    PE-001: fs module - full file system access

Risk Score: 100/100
Safe to Install: ❌ NO
```

## Output Formats

- **Terminal** (default): Color-coded TUI with severity icons, keyboard navigation
- **JSON**: Machine-readable report (`--json`)
- **Markdown**: Formatted report (`--md`)

## GitHub Action

```yaml
# .github/workflows/scan.yml
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npm install -g auto-skills-scanner
- run: auto-scanner scan .
```

Scans on every PR. Blocks merge if CRITICAL issues found.

## AI Integration (opt-in)

AI analysis is **disabled by default** — no data leaves your machine unless you opt in.

```bash
auto-scanner onboard  # configure your own API endpoint
auto-scanner analyze ./some-skill/
```

**Recommended**: [Ollama](https://ollama.com) for zero data leakage — `http://localhost:11434/v1`.

## TUI Controls

| Key | Action |
|-----|--------|
| ↑↓ | Scroll findings |
| PgUp/PgDn | Page scroll |
| 0-4 | Filter severity |
| a | AI analysis |
| j | Export JSON |
| m | Export Markdown |
| q / Esc | Quit |

## Why AUTO Scanner?

| Feature | AUTO Scanner | NVIDIA SkillSpector | Snyk Agent Scan |
|---------|-------------|-------------------|-----------------|
| **Zero dependencies** | ✅ 65kB | ❌ Python + deps | ❌ Python + deps |
| **Instant install** | ✅ `npx` | ❌ Clone + venv | ❌ Clone + venv |
| **18 CVE-mapped rules** | ✅ | 65 patterns | 15+ risks |
| **AI analysis** | ✅ Opt-in | ✅ | ❌ |
| **GitHub Action** | ✅ | ❌ | ❌ |
| **MCP server scan** | ✅ | ❌ | ✅ |
| **Offline mode** | ✅ | ✅ | ❌ |

## Roadmap

- [x] 18 detection rules (CVE-mapped)
- [x] Interactive TUI
- [x] AI-powered analysis
- [x] GitHub Action
- [x] npm package
- [ ] Real CVE feed (NVD API)
- [ ] VS Code extension
- [ ] Claude Code / Cursor plugin

## License

MIT — AUTO Security Tools
