// Rule: Permission Escalation Detection
// Detects excessive permissions, privilege escalation attempts, and sandbox escapes
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

const PERMISSION_PATTERNS = [
  // Privilege escalation
  { pattern: /\bsudo\b/g, name: 'sudo usage', desc: 'Attempting to use sudo - privilege escalation' },
  { pattern: /\brequire\s*\(\s*['\"]child_process['\"]\s*\)/g, name: 'child_process require', desc: 'Requiring Node.js child_process - enables command execution' },
  { pattern: /\brequire\s*\(\s*['\"]fs['\"]\s*\)/g, name: 'fs module require', desc: 'Requiring Node.js fs module - full file system access' },
  { pattern: /\brequire\s*\(\s*['\"]os['\"]\s*\)/g, name: 'os module require', desc: 'Requiring Node.js os module - system information access' },
  { pattern: /\brequire\s*\(\s*['\"]net['\"]\s*\)/g, name: 'net module require', desc: 'Requiring Node.js net module - network access capability' },
  // Sandbox escape
  { pattern: /\bprocess\.exit\b/g, name: 'process.exit()', desc: 'Terminating the process - could be used to escape sandbox' },
  { pattern: /\brequire\.resolve\b/g, name: 'require.resolve', desc: 'Resolving module paths - could probe system structure' },
  { pattern: /\bvm\.(runInNewContext|runInThisContext|Script)\b/g, name: 'Node.js vm module', desc: 'Using Node.js vm module - could execute arbitrary JS' },
  { pattern: /\bFunction\.prototype\.call\b/g, name: 'Function.prototype.call', desc: 'Indirect function calls - may bypass security wrappers' },
  // Excessive tool permissions
  { pattern: /"allowed_tools"\s*:\s*\[\s*"all"\s*\]/g, name: 'All tools allowed', desc: 'Agent requesting permission to use ALL tools - excessive privilege' },
  { pattern: /"allowed_tools"\s*:\s*\[\s*"[^"]*bash[^"]*"\s*,\s*"[^"]*filesystem[^"]*"\s*,\s*"[^"]*network[^"]*"/g, name: 'Bash+filesystem+network tools', desc: 'Agent requesting filesystem, bash, and network access simultaneously' },
  { pattern: /"run_as"\s*:\s*"subagent"/g, name: 'Subagent execution', desc: 'Skill configured to run as subagent - ensure proper sandboxing' },
  // Elevation in Windows
  { pattern: /\bRunAsAdministrator\b/gi, name: 'Windows admin elevation', desc: 'Attempting to run with administrator privileges' },
  { pattern: /\bSet-ExecutionPolicy\b/gi, name: 'PowerShell execution policy', desc: 'Modifying PowerShell execution policy - potential bypass' },
];

export const permissionEscalationRule: DetectionRule = {
  id: 'PE-001',
  name: 'Permission Escalation Detection',
  category: RuleCategory.PERMISSION_ESCALATION,
  severity: Severity.CRITICAL,
  description: 'Detects privilege escalation attempts, excessive tool permissions, sandbox escapes, and dangerous module imports',
  remediation: 'Use principle of least privilege. Only allow necessary tools. Run in sandboxed environment. Avoid running as root/admin.',
  cweId: 'CWE-269',
  cveIds: ['CVE-2026-0008'],
  references: [
    'https://cwe.mitre.org/data/definitions/269.html',
    'https://modelcontextprotocol.io/docs/concepts/security',
  ],
  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const { pattern, name, desc } of PERMISSION_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(new RegExp(pattern.source, pattern.flags));
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          let severity = Severity.CRITICAL;
          if (name.includes('fs module require') || name.includes('os module require')) {
            severity = Severity.MEDIUM;
          } else if (name.includes('All tools allowed') || name.includes('Subagent execution')) {
            severity = Severity.HIGH;
          }
          findings.push({
            ruleId: 'PE-001',
            ruleName: 'Permission Escalation Detection',
            category: RuleCategory.PERMISSION_ESCALATION,
            severity,
            file: filePath,
            line: i + 1,
            column: col,
            description: `${desc}: ${name}`,
            evidence: lines[i].trim(),
            remediation: 'Use principle of least privilege. Only allow necessary tools.',
            cweId: 'CWE-269',
            references: ['https://cwe.mitre.org/data/definitions/269.html'],
          });
        }
      }
    }
    return findings;
  },
};
