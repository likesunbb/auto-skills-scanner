// Rule: Configuration Poisoning Detection
// Detects attempts to maliciously modify MCP configurations, inject servers, or alter settings
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

const CONFIG_PATTERNS = [
  // MCP config manipulation
  { pattern: /\bmcp\.json\b/gi, name: 'MCP config reference', desc: 'Reference to MCP configuration file - check for unauthorized modification' },
  { pattern: /"command"\s*:\s*"(curl|wget|nc|bash|sh|cmd|powershell)"/gi, name: 'MCP server with shell command', desc: 'MCP server using a shell command instead of a proper binary' },
  { pattern: /"command"\s*:\s*"npx\s+-y\s+\S+/gi, name: 'MCP with npx remote package', desc: 'MCP server using npx with remote package - verify package source' },
  { pattern: /"url"\s*:\s*"http:\/\//gi, name: 'MCP with HTTP (not HTTPS)', desc: 'MCP server using unencrypted HTTP connection' },
  { pattern: /"url"\s*:\s*"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi, name: 'MCP with raw IP URL', desc: 'MCP server connecting to raw IP address - suspicious' },
  { pattern: /"transport"\s*:\s*"stdio".*"command".*"bash"/gis, name: 'MCP stdio via bash', desc: 'MCP server using bash as stdio command - potential shell injection' },
  // Package.json manipulation
  { pattern: /"postinstall"\s*:\s*".*(curl|wget|bash|sh|eval|exec)/gi, name: 'Suspicious postinstall script', desc: 'npm postinstall hook executing remote scripts or eval' },
  { pattern: /"preinstall"\s*:\s*".*(curl|wget)/gi, name: 'Suspicious preinstall script', desc: 'npm preinstall hook downloading external content' },
  // File system manipulation of config files
  { pattern: /\bwriteFile(Sync)?\s*\(.*mcp\.json/gi, name: 'Writing to mcp.json', desc: 'Programmatically modifying MCP configuration' },
  { pattern: /\bappendFile(Sync)?\s*\(.*mcp\.json/gi, name: 'Appending to mcp.json', desc: 'Appending to MCP configuration file' },
  { pattern: /\bcp\s+.*mcp\.json/gi, name: 'Copying mcp.json', desc: 'Copying or overwriting MCP configuration' },
];

export const configPoisoningRule: DetectionRule = {
  id: 'CP-001',
  name: 'Configuration Poisoning Detection',
  category: RuleCategory.CONFIG_POISONING,
  severity: Severity.HIGH,
  description: 'Detects attempts to maliciously modify MCP configurations, inject untrusted servers, or alter agent settings',
  remediation: 'Review all MCP server sources before adding. Use HTTPS for remote servers. Verify package identities before installing.',
  cweId: 'CWE-15',
  cveIds: ['CVE-2026-0005'],
  references: [
    'https://cwe.mitre.org/data/definitions/15.html',
    'https://modelcontextprotocol.io/docs/concepts/security',
  ],
  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const { pattern, name, desc } of CONFIG_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].matchAll(new RegExp(pattern.source, pattern.flags));
        for (const match of matches) {
          const col = match.index !== undefined ? match.index + 1 : undefined;
          let severity = Severity.HIGH;
          if (name.includes('HTTP (not HTTPS)') || name.includes('raw IP URL')) {
            severity = Severity.MEDIUM;
          }
          findings.push({
            ruleId: 'CP-001',
            ruleName: 'Configuration Poisoning Detection',
            category: RuleCategory.CONFIG_POISONING,
            severity,
            file: filePath,
            line: i + 1,
            column: col,
            description: `${desc}: ${name}`,
            evidence: lines[i].trim(),
            remediation: 'Review all MCP server sources. Use HTTPS. Verify package identities.',
            cweId: 'CWE-15',
            references: ['https://modelcontextprotocol.io/docs/concepts/security'],
          });
        }
      }
    }
    return findings;
  },
};
