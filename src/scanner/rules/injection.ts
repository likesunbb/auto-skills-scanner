// Rule: Injection Detection
// Detects prompt injection, command injection, and code injection patterns in tool calls
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

const INJECTION_PATTERNS = [
  // Prompt injection patterns in Skill descriptions
  { pattern: /\bignore\s+(all\s+)?(previous|above|prior)\s+instructions\b/gi, name: 'Prompt injection: ignore instructions', desc: 'Attempt to override system instructions' },
  { pattern: /\byou\s+are\s+now\b/gi, name: 'Prompt injection: role change', desc: 'Attempt to change agent role/persona' },
  { pattern: /\bpretend\s+(you\s+are|to\s+be)\b/gi, name: 'Prompt injection: pretend', desc: 'Pretending to be something else' },
  { pattern: /\bsystem\s*(prompt|message|instruction)\s*:\s*/gi, name: 'System prompt override', desc: 'Attempting to inject system-level instructions' },
  { pattern: /\b\[INST\]\b/g, name: 'LLM instruction tags', desc: 'Using LLM-specific instruction formatting for injection' },
  { pattern: /\b\{\{\s*[^{}]*\s*\}\}/g, name: 'Prompt template injection', desc: 'Template injection via {{ }} delimiters' },
  // Command injection in tool parameters
  { pattern: /[;&|`$]\s*(ls|id|whoami|cat|rm|wget|curl|nc|bash|sh|cmd|powershell)\b/g, name: 'Command injection in parameters', desc: 'Shell commands injected into tool parameters' },
  { pattern: /\$\(.*\)/g, name: 'Command substitution', desc: 'Shell command substitution pattern' },
  { pattern: /`[^`]+`/g, name: 'Backtick execution', desc: 'Backtick command substitution - may be injection' },
  // SQL injection in data access
  { pattern: /\bSELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=.*['\"]\s*\+/gi, name: 'SQL injection pattern', desc: 'String concatenation in SQL query - potential SQL injection' },
  // Path traversal
  { pattern: /\.\.\/\.\.\/\.\.\//g, name: 'Path traversal', desc: 'Directory traversal (../../../) attempting to access files outside scope' },
  { pattern: /\bpath\.join\s*\(\s*__dirname\s*,\s*['\"`]\.\./g, name: 'Path traversal via join', desc: 'Path traversal via path.join with parent directory' },
];

export const injectionRule: DetectionRule = {
  id: 'INJ-001',
  name: 'Injection Detection',
  category: RuleCategory.INJECTION,
  severity: Severity.HIGH,
  description: 'Detects prompt injection, command injection, SQL injection, and path traversal patterns in Skill files and tool definitions',
  remediation: 'Sanitize all user inputs before passing to LLMs or shell commands. Use parameterized queries. Validate file paths.',
  cweId: 'CWE-77',
  cveIds: ['CVE-2026-0004'],
  references: [
    'https://cwe.mitre.org/data/definitions/77.html',
    'https://www.promptingguide.ai/risks/adversarial',
  ],
  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const { pattern, name, desc } of INJECTION_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(new RegExp(pattern.source, pattern.flags));
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          findings.push({
            ruleId: 'INJ-001',
            ruleName: 'Injection Detection',
            category: RuleCategory.INJECTION,
            severity: Severity.HIGH,
            file: filePath,
            line: i + 1,
            column: col,
            description: `${desc}: ${name}`,
            evidence: lines[i].trim(),
            remediation: 'Sanitize all user inputs. Use parameterized queries. Validate file paths.',
            cweId: 'CWE-77',
            references: ['https://cwe.mitre.org/data/definitions/77.html'],
          });
        }
      }
    }
    return findings;
  },
};
