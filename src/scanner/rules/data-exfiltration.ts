// Rule: Data Exfiltration Detection
// Detects patterns that could leak sensitive data: env vars, API keys, sending to external URLs
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

const EXFIL_PATTERNS = [
  // Reading sensitive environment variables
  { pattern: /\bprocess\.env\b/g, name: 'process.env access', desc: 'Accessing environment variables - may leak secrets' },
  { pattern: /\bos\.environ\b/g, name: 'os.environ access', desc: 'Accessing OS environment variables' },
  { pattern: /\bgetenv\s*\(/g, name: 'getenv() call', desc: 'Reading environment variables' },
  // Sending data externally
  { pattern: /\bfetch\s*\(\s*['\"`]https?:\/\//g, name: 'fetch to external URL', desc: 'Making HTTP requests to external servers - check if data exfiltration' },
  { pattern: /\baxios\.(get|post|put|delete)\s*\(/g, name: 'axios request', desc: 'HTTP request via axios - check data destination' },
  { pattern: /\brequests\.(get|post|put|delete)\s*\(/g, name: 'Python requests call', desc: 'HTTP request via Python requests - check data destination' },
  { pattern: /\bXMLHttpRequest\b/g, name: 'XMLHttpRequest', desc: 'Browser HTTP request - verify data sent externally' },
  // Reading credential files
  { pattern: /\.(env|secret|credential|token|key|pem)\b/g, name: 'Credential file reference', desc: 'Referencing credential/secret files' },
  { pattern: /\bapi[_-]?key\b/gi, name: 'API key variable', desc: 'Potential API key in code - should be in env vars' },
  { pattern: /\bpassword\s*[:=]\s*['\"]\S+['\"]/gi, name: 'Hardcoded password', desc: 'Hardcoded password in source code' },
  { pattern: /\bsecret\s*[:=]\s*['\"]\S+['\"]/gi, name: 'Hardcoded secret', desc: 'Hardcoded secret in source code' },
  { pattern: /\btoken\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]/gi, name: 'Hardcoded token', desc: 'Hardcoded authentication token' },
  // File exfiltration
  { pattern: /\breadFileSync\s*\(/g, name: 'readFileSync', desc: 'Reading files - could be exfiltrating sensitive data' },
  { pattern: /\bcopyFileSync\s*\(/g, name: 'copyFileSync', desc: 'Copying files - could be moving sensitive data' },
  // Data serialization for export
  { pattern: /\bJSON\.stringify\s*\(\s*process\.env/g, name: 'JSON.stringify(process.env)', desc: 'Serializing all environment variables - likely exfiltration' },
];

export const dataExfiltrationRule: DetectionRule = {
  id: 'DE-001',
  name: 'Data Exfiltration Detection',
  category: RuleCategory.DATA_EXFILTRATION,
  severity: Severity.HIGH,
  description: 'Detects patterns indicative of data exfiltration: reading env vars, sending data to external URLs, hardcoded secrets',
  remediation: 'Store secrets in environment variables or secret managers. Restrict network access. Never hardcode credentials.',
  cweId: 'CWE-200',
  cveIds: ['CVE-2026-0002'],
  references: [
    'https://cwe.mitre.org/data/definitions/200.html',
    'https://owasp.org/www-project-top-ten/',
  ],
  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const { pattern, name, desc } of EXFIL_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(new RegExp(pattern.source, pattern.flags));
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          let severity = Severity.HIGH;
          // Downgrade some less critical patterns
          if (name.includes('process.env access') || name.includes('os.environ access')) {
            severity = Severity.MEDIUM;
          }
          findings.push({
            ruleId: 'DE-001',
            ruleName: 'Data Exfiltration Detection',
            category: RuleCategory.DATA_EXFILTRATION,
            severity,
            file: filePath,
            line: i + 1,
            column: col,
            description: `${desc}: ${name}`,
            evidence: lines[i].trim(),
            remediation: 'Store secrets in environment variables or secret managers. Restrict network access.',
            cweId: 'CWE-200',
            references: ['https://cwe.mitre.org/data/definitions/200.html'],
          });
        }
      }
    }
    return findings;
  },
};
