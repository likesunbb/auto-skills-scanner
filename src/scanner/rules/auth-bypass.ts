// Rule: Authentication Bypass Detection
// Detects hardcoded credentials, weak auth patterns, missing authentication checks
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

const AUTH_PATTERNS = [
  // Hardcoded tokens/keys
  { pattern: /(['\"])(sk-[A-Za-z0-9]{20,})\1/g, name: 'OpenAI/API key', desc: 'Hardcoded API key (sk-... pattern)' },
  { pattern: /(['\"])(ghp_[A-Za-z0-9]{36})\1/g, name: 'GitHub personal access token', desc: 'Hardcoded GitHub PAT' },
  { pattern: /(['\"])(gho_[A-Za-z0-9]{36})\1/g, name: 'GitHub OAuth token', desc: 'Hardcoded GitHub OAuth token' },
  { pattern: /(['\"])(xox[baprs]-[A-Za-z0-9-]{10,})\1/g, name: 'Slack token', desc: 'Hardcoded Slack API token' },
  { pattern: /(['\"])(AKIA[0-9A-Z]{16})\1/g, name: 'AWS Access Key', desc: 'Hardcoded AWS access key ID' },
  { pattern: /(['\"])(AIza[0-9A-Za-z\-_]{35})\1/g, name: 'Google API key', desc: 'Hardcoded Google API key' },
  // Weak authentication checks
  { pattern: /\bif\s*\(\s*true\s*\)\s*\{?\s*(return|grant|allow|authorize)/g, name: 'Always-true auth check', desc: 'Authentication check that always passes' },
  { pattern: /\bauth\s*=\s*false\b/gi, name: 'Auth disabled flag', desc: 'Authentication explicitly disabled' },
  { pattern: /\bcheckAuth\s*\(\s*\)\s*\{\s*return\s+true\s*;?\s*\}/g, name: 'checkAuth always returns true', desc: 'No-op authentication check' },
  { pattern: /\bAuthorization\s*:\s*['\"]Basic\s+[A-Za-z0-9+/=]+['\"]/g, name: 'Hardcoded Basic auth', desc: 'Hardcoded Basic authentication header' },
  { pattern: /\bBearer\s+[A-Za-z0-9_\-\.]{20,}/g, name: 'Hardcoded Bearer token', desc: 'Hardcoded JWT or bearer token in source' },
  // Missing auth in MCP config
  { pattern: /"transport"\s*:\s*"(sse|streamable-http)"/g, name: 'Remote MCP transport', desc: 'Remote MCP server transport - ensure authentication is configured' },
];

export const authBypassRule: DetectionRule = {
  id: 'AB-001',
  name: 'Authentication Bypass Detection',
  category: RuleCategory.AUTH_BYPASS,
  severity: Severity.CRITICAL,
  description: 'Detects hardcoded credentials, API keys, tokens, and weak authentication patterns in Skill and MCP configurations',
  remediation: 'Never hardcode credentials. Use environment variables or secret managers. Implement proper authentication checks.',
  cweId: 'CWE-798',
  cveIds: ['CVE-2026-0003'],
  references: [
    'https://cwe.mitre.org/data/definitions/798.html',
    'https://cwe.mitre.org/data/definitions/287.html',
  ],
  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const { pattern, name, desc } of AUTH_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(new RegExp(pattern.source, pattern.flags));
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          let severity = Severity.CRITICAL;
          if (name.includes('Remote MCP transport')) {
            severity = Severity.MEDIUM;
          }
          findings.push({
            ruleId: 'AB-001',
            ruleName: 'Authentication Bypass Detection',
            category: RuleCategory.AUTH_BYPASS,
            severity,
            file: filePath,
            line: i + 1,
            column: col,
            description: `${desc}: ${name}`,
            evidence: lines[i].trim(),
            remediation: 'Never hardcode credentials. Use environment variables or secret managers.',
            cweId: 'CWE-798',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
          });
        }
      }
    }
    return findings;
  },
};
