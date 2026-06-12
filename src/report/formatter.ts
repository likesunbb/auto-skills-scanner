// Report Formatter — JSON and Markdown output
import { Finding, ScanResult, Severity, RuleCategory } from '../types';

const CATEGORY_LABELS: Record<RuleCategory, string> = {
  [RuleCategory.CODE_EXECUTION]: 'Code Execution',
  [RuleCategory.DATA_EXFILTRATION]: 'Data Exfiltration',
  [RuleCategory.AUTH_BYPASS]: 'Auth Bypass',
  [RuleCategory.INJECTION]: 'Injection',
  [RuleCategory.CONFIG_POISONING]: 'Config Poisoning',
  [RuleCategory.BEHAVIOR_ANOMALY]: 'Behavior Anomaly',
  [RuleCategory.DEPENDENCY_CHAIN]: 'Dependency Chain',
  [RuleCategory.PERMISSION_ESCALATION]: 'Permission Escalation',
};

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function formatMarkdown(result: ScanResult): string {
  const { meta, summary, findings } = result;
  let md = '';

  md += '# AUTO Skills Scanner — Scan Report\n\n';
  md += '**Target**: `' + meta.targetPath + '`\n';
  md += '**Scanned**: ' + meta.totalFiles + ' files in ' + meta.durationMs + 'ms\n';
  md += '**Scanner**: v' + meta.scannerVersion + '\n\n';

  md += '## Risk Assessment\n\n';
  md += '| Metric | Value |\n|--------|-------|\n';
  md += '| **Risk Score** | **' + summary.riskScore + '/100** |\n';
  md += '| **Safe to Install** | ' + (summary.safeToInstall ? 'Yes' : 'No') + ' |\n';
  md += '| **Total Findings** | ' + summary.totalFindings + ' |\n\n';

  md += '### By Severity\n\n| Severity | Count |\n|----------|-------|\n';
  for (const [severity, count] of Object.entries(summary.bySeverity) as [Severity, number][]) {
    if (count > 0) md += '| ' + severity + ' | ' + count + ' |\n';
  }
  md += '\n';

  md += '### By Category\n\n| Category | Count |\n|----------|-------|\n';
  for (const [category, count] of Object.entries(summary.byCategory) as [RuleCategory, number][]) {
    if (count > 0) md += '| ' + (CATEGORY_LABELS[category] || category) + ' | ' + count + ' |\n';
  }
  md += '\n';

  if (findings.length > 0) {
    md += '## Findings (' + findings.length + ')\n\n';
    const sorted = [...findings].sort(severityOrder);
    for (let i = 0; i < sorted.length; i++) {
      const f = sorted[i];
      md += '### ' + (i + 1) + '. ' + f.ruleName + ' — ' + f.severity + '\n\n';
      md += '| Field | Value |\n|-------|-------|\n';
      md += '| **Rule** | ' + f.ruleId + ' |\n';
      md += '| **Category** | ' + (CATEGORY_LABELS[f.category] || f.category) + ' |\n';
      md += '| **Severity** | ' + f.severity + ' |\n';
      md += '| **File** | `' + f.file + '` |\n';
      if (f.line) md += '| **Line** | ' + f.line + (f.column ? ':' + f.column : '') + ' |\n';
      if (f.cveIds) md += '| **CVE** | ' + f.cveIds.join(', ') + ' |\n';
      if (f.cweId) md += '| **CWE** | ' + f.cweId + ' |\n';
      md += '\n**Description**: ' + f.description + '\n\n';
      if (f.evidence) md += '```\n' + f.evidence + '\n```\n\n';
      md += '**Remediation**: ' + f.remediation + '\n\n---\n\n';
    }
  } else {
    md += '## Findings\n\nNo issues detected.\n\n';
  }

  return md;
}

function severityOrder(a: Finding, b: Finding): number {
  const order: Severity[] = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO];
  return order.indexOf(a.severity) - order.indexOf(b.severity);
}
