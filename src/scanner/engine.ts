// Scanner Engine
// Core orchestrator: walks scanned directories, runs detection rules, collects findings
import * as fs from 'fs';
import * as path from 'path';
import {
  Finding, ScanResult, ScanMeta, ScanSummary,
  Severity, RuleCategory, ScannedFile,
} from '../types';
import { allRules } from './rules/index';
import { scanSkillDirectory } from './parsers/skill-parser';
import { findMcpConfigs, parseMcpConfig, validateMcpServer } from './parsers/mcp-parser';

const SCANNER_VERSION = '0.1.0';

/** Run a full scan against a target path (Skill directory or MCP config) */
export async function scan(targetPath: string): Promise<ScanResult> {
  const startedAt = new Date();
  const absPath = path.resolve(targetPath);

  if (!fs.existsSync(absPath)) {
    throw new Error(`Target path does not exist: ${absPath}`);
  }

  const allFindings: Finding[] = [];
  let totalFiles = 0;

  // Determine what we're scanning
  const stat = fs.statSync(absPath);

  if (stat.isDirectory()) {
    // Scan as a Skill directory
    const files = scanSkillDirectory(absPath);
    totalFiles = files.length;

    for (const file of files) {
      const findings = await scanFile(file);
      allFindings.push(...findings);
    }

    // Also check for MCP configs in the directory
    const mcpConfigs = findMcpConfigs(absPath);
    for (const configPath of mcpConfigs) {
      const config = parseMcpConfig(configPath);
      if (config) {
        totalFiles++;
        // Validate each MCP server
        for (const server of config.servers) {
          const validation = validateMcpServer(server);
          for (const issue of validation.issues) {
            allFindings.push({
              ruleId: 'MCP-VAL-001',
              ruleName: 'MCP Server Validation',
              category: RuleCategory.CONFIG_POISONING,
              severity: issue.severity as Severity,
              file: path.relative(absPath, configPath),
              description: `${server.name}: ${issue.issue}`,
              remediation: issue.recommendation,
              cweId: 'CWE-15',
            });
          }
        }
      }
    }
  } else {
    // Scan single file
    try {
      const content = fs.readFileSync(absPath, 'utf-8');
      const ext = path.extname(absPath);
      const fileStat = fs.statSync(absPath);
      const file: ScannedFile = {
        path: path.basename(absPath),
        content,
        ext,
        size: fileStat.size,
      };
      totalFiles = 1;
      const findings = await scanFile(file);
      allFindings.push(...findings);
    } catch {
      throw new Error(`Cannot read file: ${absPath}`);
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

/** Scan a single file against all detection rules */
async function scanFile(file: ScannedFile): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const rule of allRules) {
    try {
      // Skip rules that don't apply to this file type
      if (!shouldApplyRule(rule.id, file)) {
        continue;
      }

      const result = rule.check(file.content, file.path);
      if (result) {
        if (Array.isArray(result)) {
          findings.push(...result);
        } else {
          findings.push(result);
        }
      }
    } catch {
      // Rule execution error - skip this rule, continue with others
    }
  }

  return findings;
}

/** Determine if a rule should be applied to a given file */
function shouldApplyRule(ruleId: string, file: ScannedFile): boolean {
  const ext = file.ext.toLowerCase();
  const fileName = path.basename(file.path).toLowerCase();

  // Code execution: apply to scripts
  if (ruleId === 'CE-001') {
    return ['.ts', '.js', '.py', '.sh', '.ps1', '.mjs', '.cjs'].includes(ext);
  }

  // Data exfiltration: apply to scripts and configs
  if (ruleId === 'DE-001') {
    return ['.ts', '.js', '.py', '.sh', '.env', '.json', '.yaml', '.yml'].includes(ext) ||
           fileName === 'skill.md' || fileName === 'dockerfile';
  }

  // Auth bypass: apply to all files (secrets could be anywhere)
  if (ruleId === 'AB-001') {
    return true;
  }

  // Injection: apply to Skill definitions and scripts
  if (ruleId === 'INJ-001') {
    return ['.md', '.ts', '.js', '.py', '.yaml', '.yml'].includes(ext) ||
           fileName === 'skill.md';
  }

  // Config poisoning: apply to config files and scripts
  if (ruleId === 'CP-001') {
    return ['.json', '.yaml', '.yml', '.ts', '.js'].includes(ext) ||
           fileName === 'mcp.json' || fileName === '.mcp.json';
  }

  // Behavior anomaly: apply to scripts
  if (ruleId === 'BA-001') {
    return ['.ts', '.js', '.py', '.sh', '.ps1'].includes(ext);
  }

  // Dependency chain: apply to package files
  if (ruleId === 'DC-001') {
    return fileName === 'package.json' || fileName === 'requirements.txt' ||
           fileName === 'pyproject.toml' || fileName === 'pipfile' ||
           fileName === 'gemfile';
  }

  // Permission escalation: apply to scripts and configs
  if (ruleId === 'PE-001') {
    return ['.ts', '.js', '.py', '.sh', '.ps1', '.json', '.md'].includes(ext) ||
           fileName === 'skill.md';
  }

  return true;
}

/** Compute summary statistics from findings */
function computeSummary(findings: Finding[]): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  const byCategory: Record<RuleCategory, number> = {
    [RuleCategory.CODE_EXECUTION]: 0,
    [RuleCategory.DATA_EXFILTRATION]: 0,
    [RuleCategory.AUTH_BYPASS]: 0,
    [RuleCategory.INJECTION]: 0,
    [RuleCategory.CONFIG_POISONING]: 0,
    [RuleCategory.BEHAVIOR_ANOMALY]: 0,
    [RuleCategory.DEPENDENCY_CHAIN]: 0,
    [RuleCategory.PERMISSION_ESCALATION]: 0,
  };

  for (const finding of findings) {
    bySeverity[finding.severity]++;
    byCategory[finding.category]++;
  }

  // Compute risk score (0-100)
  const weights: Record<Severity, number> = {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 8,
    LOW: 3,
    INFO: 1,
  };

  let rawScore = 0;
  for (const [severity, count] of Object.entries(bySeverity)) {
    rawScore += count * (weights[severity as Severity] || 1);
  }
  // Cap at 100
  const riskScore = Math.min(100, Math.round(rawScore));

  // Safe to install: no CRITICAL findings and risk score < 40
  const safeToInstall = bySeverity[Severity.CRITICAL] === 0 && riskScore < 40;

  return {
    bySeverity,
    byCategory,
    totalFindings: findings.length,
    riskScore,
    safeToInstall,
  };
}
