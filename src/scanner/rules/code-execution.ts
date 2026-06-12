// Rule: Code Execution Detection
// Detects unsafe code execution patterns: eval, exec, subprocess without sandboxing
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

const DANGEROUS_PATTERNS = [
  // JavaScript/TypeScript
  { pattern: /\beval\s*\(/g, name: 'eval() call', desc: 'Use of eval() allows arbitrary code execution' },
  { pattern: /\bnew\s+Function\s*\(/g, name: 'new Function()', desc: 'Dynamic function constructor allows arbitrary code execution' },
  { pattern: /\bexec\s*\(/g, name: 'exec() call', desc: 'Command execution without sandboxing' },
  { pattern: /\bspawn\s*\(/g, name: 'spawn() call', desc: 'Child process spawn without sandbox restrictions' },
  { pattern: /\bchild_process\b/g, name: 'child_process import', desc: 'Using Node.js child_process module - ensure sandboxing' },
  { pattern: /\bexecSync\s*\(/g, name: 'execSync() call', desc: 'Synchronous command execution - potential RCE' },
  { pattern: /\bspawnSync\s*\(/g, name: 'spawnSync() call', desc: 'Synchronous process spawn - potential RCE' },
  // Python
  { pattern: /\bos\.system\s*\(/g, name: 'os.system() call', desc: 'Python os.system() allows arbitrary shell commands' },
  { pattern: /\bos\.popen\s*\(/g, name: 'os.popen() call', desc: 'Python os.popen() allows command execution' },
  { pattern: /\bsubprocess\.(call|run|Popen)\s*\(/g, name: 'subprocess call', desc: 'Python subprocess execution without sandbox' },
  { pattern: /\bexec\s*\(\s*compile\b/g, name: 'exec(compile()) pattern', desc: 'Dynamic code compilation and execution' },
  // Shell scripts
  { pattern: /\bcurl\s+\S+\s*\|\s*(ba)?sh\b/g, name: 'curl pipe to shell', desc: 'Downloading and executing remote scripts - classic supply chain attack' },
  { pattern: /\bwget\s+\S+\s*-O\s*-\s*\|\s*(ba)?sh\b/g, name: 'wget pipe to shell', desc: 'Downloading and executing remote scripts' },
];

export const codeExecutionRule: DetectionRule = {
  id: 'CE-001',
  name: 'Code Execution Detection',
  category: RuleCategory.CODE_EXECUTION,
  severity: Severity.CRITICAL,
  description: 'Detects potentially unsafe code execution patterns including eval(), child_process, subprocess, and curl-pipe-shell',
  remediation: 'Run all external command execution inside a restricted sandbox with CPU/memory/network limits. Never eval() untrusted input.',
  cweId: 'CWE-94',
  cveIds: ['CVE-2026-0001', 'CVE-2025-0002'],
  references: [
    'https://owasp.org/www-community/attacks/Code_Injection',
    'https://cwe.mitre.org/data/definitions/94.html',
  ],
  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const { pattern, name, desc } of DANGEROUS_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(pattern);
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          findings.push({
            ruleId: 'CE-001',
            ruleName: 'Code Execution Detection',
            category: RuleCategory.CODE_EXECUTION,
            severity: Severity.CRITICAL,
            file: filePath,
            line: i + 1,
            column: col,
            description: `${desc}: ${name}`,
            evidence: lines[i].trim(),
            remediation: 'Run all external command execution inside a restricted sandbox with CPU/memory/network limits',
            cweId: 'CWE-94',
            cveIds: ['CVE-2026-0001'],
            references: ['https://owasp.org/www-community/attacks/Code_Injection'],
          });
        }
      }
    }
    return findings;
  },
};
