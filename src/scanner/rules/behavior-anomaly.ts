// Rule: Behavior Anomaly Detection
// Detects unexpected file operations, network calls, and suspicious behavior patterns
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

const ANOMALY_PATTERNS = [
  // Unexpected file operations
  { pattern: /\bunlink(Sync)?\s*\(/g, name: 'File deletion (unlink)', desc: 'Deleting files - check if targeting config or credential files' },
  { pattern: /\brmdir(Sync)?\s*\(/g, name: 'Directory removal', desc: 'Removing directories - verify not deleting important config' },
  { pattern: /\brename(Sync)?\s*\(/g, name: 'File rename', desc: 'Renaming files - could be hiding or moving files maliciously' },
  { pattern: /\bchmod\s*\(/g, name: 'File permission change', desc: 'Changing file permissions - could make files executable' },
  { pattern: /\bfs\.writeFile.*\.ssh\b/gi, name: 'Writing to .ssh', desc: 'Writing to SSH directory - potential backdoor' },
  { pattern: /\bfs\.writeFile.*\.bashrc\b/gi, name: 'Writing to .bashrc', desc: 'Modifying shell config - persistence mechanism' },
  // Suspicious network patterns
  { pattern: /\bhttp\.(createServer|listen)\s*\(/g, name: 'HTTP server creation', desc: 'Creating an HTTP server - verify legitimate purpose' },
  { pattern: /\bnet\.(connect|createConnection)\s*\(/g, name: 'Network connection', desc: 'Opening network connections - verify destination' },
  { pattern: /\bWebSocket\b/g, name: 'WebSocket usage', desc: 'WebSocket connection - could be used for C2 communication' },
  { pattern: /\bdns\.(lookup|resolve)\s*\(/g, name: 'DNS lookup', desc: 'Performing DNS lookups - possible data exfiltration via DNS' },
  // Persistence mechanisms
  { pattern: /\b(crontab|schtasks)\b/gi, name: 'Task scheduling', desc: 'Scheduling system tasks - potential persistence mechanism' },
  { pattern: /\b(startup|autostart|launchd)\b/gi, name: 'Startup registration', desc: 'Registering for system startup - persistence mechanism' },
  { pattern: /\bregistry\b/gi, name: 'Registry access', desc: 'Windows registry access - may be modifying system configuration' },
];

export const behaviorAnomalyRule: DetectionRule = {
  id: 'BA-001',
  name: 'Behavior Anomaly Detection',
  category: RuleCategory.BEHAVIOR_ANOMALY,
  severity: Severity.MEDIUM,
  description: 'Detects unexpected file operations, network connections, and persistence mechanisms that indicate anomalous agent behavior',
  remediation: 'Restrict file operations to necessary paths. Limit network access. Monitor for persistence mechanisms. Use sandbox execution.',
  cweId: 'CWE-912',
  cveIds: ['CVE-2026-0006'],
  references: [
    'https://cwe.mitre.org/data/definitions/912.html',
  ],
  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const { pattern, name, desc } of ANOMALY_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(new RegExp(pattern.source, pattern.flags));
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          let severity = Severity.MEDIUM;
          if (name.includes('Writing to .ssh') || name.includes('Writing to .bashrc') || name.includes('Persistence')) {
            severity = Severity.HIGH;
          }
          findings.push({
            ruleId: 'BA-001',
            ruleName: 'Behavior Anomaly Detection',
            category: RuleCategory.BEHAVIOR_ANOMALY,
            severity,
            file: filePath,
            line: i + 1,
            column: col,
            description: `${desc}: ${name}`,
            evidence: lines[i].trim(),
            remediation: 'Restrict file operations. Limit network access. Use sandbox execution.',
            cweId: 'CWE-912',
          });
        }
      }
    }
    return findings;
  },
};
