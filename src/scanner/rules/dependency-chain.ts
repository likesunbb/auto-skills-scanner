// Rule: Dependency Chain Detection
// Detects vulnerable, unmaintained, or suspicious dependencies in package.json / requirements.txt
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

const DEPENDENCY_RISK_PATTERNS = [
  // Suspicious dependency sources
  { pattern: /"([^"]+)":\s*"(git\+https?:\/\/[^"]+)"/g, name: 'Git dependency', desc: 'Dependency pulling directly from git repository - verify source' },
  { pattern: /"([^"]+)":\s*"(file:\/\/[^"]+)"/g, name: 'Local file dependency', desc: 'Dependency from local file path - unusual for published packages' },
  { pattern: /"([^"]+)":\s*"(https?:\/\/[^"]+\.tgz)"/g, name: 'Remote tarball dependency', desc: 'Dependency from remote tarball URL - verify source integrity' },
  // Unpinned versions (supply chain risk)
  { pattern: /"([^"]+)":\s*"\*"/g, name: 'Wildcard version', desc: 'Dependency using wildcard version - may pull malicious updates' },
  { pattern: /"([^"]+)":\s*">=?\s*\d+\.\d+\.\d+"/g, name: 'Unbounded version range', desc: 'Dependency with unbounded upper version - supply chain risk' },
  { pattern: /"([^"]+)":\s*"latest"/gi, name: 'Latest version tag', desc: 'Dependency using "latest" tag - always pulls newest version' },
  // Known vulnerable packages (partial list - expand with CVE database)
  { pattern: /"([^"]+)":\s*"[^"]*"/g, name: 'npm dependency', desc: 'All npm dependencies should be checked against vulnerability databases' },
  // Python dependency risks
  { pattern: /^([a-zA-Z0-9_-]+)\s*([><=!]+)\s*\d+\.\d+\.\d+.*#egg=/gm, name: 'Python egg dependency', desc: 'Python dependency with egg link - verify source' },
  { pattern: /--index-url\s+(https?:\/\/[^\s]+)/g, name: 'Custom pip index', desc: 'Using custom pip index URL - verify trustworthiness' },
  // Suspicious install scripts
  { pattern: /"scripts"\s*:\s*\{[^}]*"(pre|post)install"[^}]*\}/g, name: 'Install scripts', desc: 'Package has install lifecycle scripts - review for malicious code' },
];

// Known vulnerable packages with CVEs (sample - extend with full database)
const KNOWN_VULNERABLE: Array<{ name: string; cve: string; severity: Severity }> = [
  { name: 'lodash', cve: 'CVE-2021-23337', severity: Severity.HIGH },
  { name: 'minimist', cve: 'CVE-2021-44906', severity: Severity.HIGH },
  { name: 'node-fetch', cve: 'CVE-2022-0235', severity: Severity.MEDIUM },
  { name: 'axios', cve: 'CVE-2023-45857', severity: Severity.MEDIUM },
  { name: 'semver', cve: 'CVE-2022-25883', severity: Severity.MEDIUM },
  { name: 'protobufjs', cve: 'CVE-2023-36665', severity: Severity.HIGH },
  { name: 'follow-redirects', cve: 'CVE-2024-28849', severity: Severity.HIGH },
];

export const dependencyChainRule: DetectionRule = {
  id: 'DC-001',
  name: 'Dependency Chain Detection',
  category: RuleCategory.DEPENDENCY_CHAIN,
  severity: Severity.HIGH,
  description: 'Detects risky dependency sources, unpinned versions, known vulnerable packages, and suspicious install scripts',
  remediation: 'Pin all dependency versions. Use lockfiles. Verify package sources. Run npm audit / pip audit regularly.',
  cweId: 'CWE-1104',
  cveIds: ['CVE-2026-0007'],
  references: [
    'https://cwe.mitre.org/data/definitions/1104.html',
    'https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities',
  ],
  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    // Check for risky dependency patterns
    for (const { pattern, name, desc } of DEPENDENCY_RISK_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(new RegExp(pattern.source, pattern.flags));
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          let severity = Severity.HIGH;
          if (name === 'npm dependency') {
            continue; // Skip generic dep listing - handled by known vuln check below
          }
          findings.push({
            ruleId: 'DC-001',
            ruleName: 'Dependency Chain Detection',
            category: RuleCategory.DEPENDENCY_CHAIN,
            severity,
            file: filePath,
            line: i + 1,
            column: col,
            description: `${desc}: ${name}`,
            evidence: lines[i].trim(),
            remediation: 'Pin dependency versions. Use lockfiles. Verify package sources.',
            cweId: 'CWE-1104',
          });
        }
      }
    }

    // Check for known vulnerable packages
    for (const vuln of KNOWN_VULNERABLE) {
      const pkgPattern = new RegExp(`"(${vuln.name})"\\s*:\\s*"([^"]*)"`, 'g');
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(pkgPattern);
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          findings.push({
            ruleId: 'DC-001',
            ruleName: 'Dependency Chain Detection',
            category: RuleCategory.DEPENDENCY_CHAIN,
            severity: vuln.severity,
            file: filePath,
            line: i + 1,
            column: col,
            description: `Known vulnerable package: ${vuln.name} (${vuln.cve}), version ${match[2]}`,
            evidence: lines[i].trim(),
            remediation: `Update ${vuln.name} to a patched version. See ${vuln.cve}.`,
            cweId: 'CWE-1104',
            cveIds: [vuln.cve],
          });
        }
      }
    }

    return findings;
  },
};
