// Scanner Engine v0.2.0
// Core orchestrator: walks scanned directories, runs detection rules, collects findings
// Supports: ignore configs, self-scan prevention, inline ignore comments
import * as fs from 'fs';
import * as path from 'path';
import {
  Finding, ScanResult, ScanMeta, ScanSummary,
  Severity, RuleCategory, ScannedFile, ScanOptions,
} from '../types';
import { allRules } from './rules/index';
import { scanSkillDirectory } from './parsers/skill-parser';
import { findMcpConfigs, parseMcpConfig, validateMcpServer } from './parsers/mcp-parser';

const SCANNER_VERSION = '0.2.0';

const DEFAULT_IGNORE = [
  '**/node_modules/**', '**/.git/**', '**/dist/**',
  '**/__pycache__/**', '**/.venv/**', '**/test-fixtures/**',
];

const LINE_IGNORE_DEFAULTS: RegExp[] = [
  /^\s*\/\/\s*(scanner|auto-scanner)\s*:\s*ignore/i,
];

// Markers that identify scanner source files (self-scan prevention)
const SCANNER_SOURCE_MARKERS = [
  'DetectionRule', 'DANGEROUS_PATTERNS', 'EXFIL_PATTERNS',
  'AUTH_PATTERNS', 'INJECTION_PATTERNS', 'CONFIG_PATTERNS',
  'ANOMALY_PATTERNS', 'DEPENDENCY_RISK_PATTERNS',
  'PERMISSION_PATTERNS', 'KNOWN_VULNERABLE',
  'from \'./scanner/', 'from \'../scanner/',
  'export async function scan(',  // engine signature
  'const SCANNER_VERSION',
];

export async function scan(targetPath: string, options?: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date();
  const absPath = path.resolve(targetPath);

  if (!fs.existsSync(absPath)) {
    throw new Error('Target path does not exist: ' + absPath);
  }

  const allFindings: Finding[] = [];
  let totalFiles = 0;

  const ignorePatterns = [...DEFAULT_IGNORE, ...(options?.ignorePaths || [])];
  const rulesToSkip = options?.skipRules || [];
  const lineIgnorePatterns: RegExp[] = options?.ignoreLinePatterns || LINE_IGNORE_DEFAULTS;

  const stat = fs.statSync(absPath);

  if (stat.isDirectory()) {
    const files = scanSkillDirectory(absPath);
    totalFiles = files.length;

    for (const file of files) {
      if (isIgnored(file.path, ignorePatterns)) continue;
      if (isScannerSource(file)) continue;
      const findings = await scanFile(file, rulesToSkip, lineIgnorePatterns);
      allFindings.push(...findings);
    }

    const mcpConfigs = findMcpConfigs(absPath);
    for (const configPath of mcpConfigs) {
      const relPath = path.relative(absPath, configPath);
      if (isIgnored(relPath, ignorePatterns)) continue;
      const config = parseMcpConfig(configPath);
      if (config) {
        totalFiles++;
        for (const server of config.servers) {
          const validation = validateMcpServer(server);
          for (const issue of validation.issues) {
            allFindings.push({
              ruleId: 'MCP-VAL-001', ruleName: 'MCP Server Validation',
              category: RuleCategory.CONFIG_POISONING,
              severity: issue.severity as Severity,
              file: relPath,
              description: server.name + ': ' + issue.issue,
              remediation: issue.recommendation,
              cweId: 'CWE-15',
            });
          }
        }
      }
    }
  } else {
    try {
      const content = fs.readFileSync(absPath, 'utf-8');
      const fileName = path.basename(absPath);
      const fileStat = fs.statSync(absPath);
      const file: ScannedFile = {
        path: fileName, content,
        ext: path.extname(absPath), size: fileStat.size,
      };
      totalFiles = 1;
      if (!isIgnored(fileName, ignorePatterns) && !isScannerSource(file)) {
        const findings = await scanFile(file, rulesToSkip, lineIgnorePatterns);
        allFindings.push(...findings);
      }
    } catch {
      throw new Error('Cannot read file: ' + absPath);
    }
  }

  const finishedAt = new Date();
  const summary = computeSummary(allFindings);

  return {
    meta: {
      scannerVersion: SCANNER_VERSION,
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      targetPath: absPath,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      totalFiles,
    },
    findings: allFindings,
    summary,
  };
}

function isScannerSource(file: ScannedFile): boolean {
  // Count how many markers match - if >= 2, definitely scanner source
  let matches = 0;
  for (const m of SCANNER_SOURCE_MARKERS) {
    if (file.content.includes(m)) matches++;
    if (matches >= 2) return true;
  }
  return false;
}

function isIgnored(filePath: string, patterns: string[]): boolean {
  return patterns.some(p => {
    const regex = new RegExp(
      '^' + p.replace(/\./g, '\\.').replace(/\*\*/g, '<<<G>>>').replace(/\*/g, '[^/]*').replace(/<<<G>>>/g, '.*') + '$'
    );
    return regex.test(filePath.replace(/\\/g, '/'));
  });
}

async function scanFile(
  file: ScannedFile, skipRules: string[], lineIgnorePatterns: RegExp[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const lines = file.content.split('\n');
  const ignoreLineIndices = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    if (lineIgnorePatterns.some(pat => pat.test(lines[i]))) {
      ignoreLineIndices.add(i);
    }
  }

  for (const rule of allRules) {
    if (skipRules.includes(rule.id)) continue;
    try {
      if (!shouldApplyRule(rule.id, file)) continue;
      const result = rule.check(file.content, file.path);
      if (result) {
        const items = Array.isArray(result) ? result : [result];
        const filtered = items.filter(f => f.line === undefined || !ignoreLineIndices.has(f.line - 1));
        findings.push(...filtered);
      }
    } catch { /* skip */ }
  }
  return findings;
}

function shouldApplyRule(ruleId: string, file: ScannedFile): boolean {
  const ext = file.ext.toLowerCase();
  const fn = path.basename(file.path).toLowerCase();
  switch (ruleId) {
    case 'CE-001': return ['.ts','.js','.py','.sh','.ps1','.mjs','.cjs'].includes(ext);
    case 'DE-001': return ['.ts','.js','.py','.sh','.env','.json','.yaml','.yml'].includes(ext) || fn === 'skill.md' || fn === 'dockerfile';
    case 'AB-001': return true;
    case 'INJ-001': return ['.md','.ts','.js','.py','.yaml','.yml'].includes(ext) || fn === 'skill.md';
    case 'CP-001': return ['.json','.yaml','.yml','.ts','.js'].includes(ext) || fn === 'mcp.json' || fn === '.mcp.json';
    case 'BA-001': return ['.ts','.js','.py','.sh','.ps1'].includes(ext);
    case 'DC-001': return ['package.json','requirements.txt','pyproject.toml','pipfile','gemfile'].includes(fn);
    case 'PE-001': return ['.ts','.js','.py','.sh','.ps1','.json','.md'].includes(ext) || fn === 'skill.md';
    default: return true;
  }
}

function computeSummary(findings: Finding[]): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    [Severity.CRITICAL]: 0, [Severity.HIGH]: 0, [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0, [Severity.INFO]: 0,
  };
  const byCategory: Record<RuleCategory, number> = {
    [RuleCategory.CODE_EXECUTION]: 0, [RuleCategory.DATA_EXFILTRATION]: 0,
    [RuleCategory.AUTH_BYPASS]: 0, [RuleCategory.INJECTION]: 0,
    [RuleCategory.CONFIG_POISONING]: 0, [RuleCategory.BEHAVIOR_ANOMALY]: 0,
    [RuleCategory.DEPENDENCY_CHAIN]: 0, [RuleCategory.PERMISSION_ESCALATION]: 0,
  };
  for (const f of findings) { bySeverity[f.severity]++; byCategory[f.category]++; }
  const weights: Record<Severity, number> = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 1 };
  let rawScore = 0;
  for (const [s, c] of Object.entries(bySeverity) as [Severity, number][]) { rawScore += c * (weights[s] || 1); }
  const riskScore = Math.min(100, Math.round(rawScore));
  const safeToInstall = bySeverity[Severity.CRITICAL] === 0 && riskScore < 40;
  return { bySeverity, byCategory, totalFindings: findings.length, riskScore, safeToInstall };
}
