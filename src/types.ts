// AUTO Skills Scanner — Core Type Definitions
// VirusTotal for Agent Skills: pre-installation supply chain security scanning

/** Severity levels for detected issues */
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

/** Risk categories for detection rules */
export enum RuleCategory {
  CODE_EXECUTION = 'code-execution',
  DATA_EXFILTRATION = 'data-exfiltration',
  AUTH_BYPASS = 'auth-bypass',
  INJECTION = 'injection',
  CONFIG_POISONING = 'config-poisoning',
  BEHAVIOR_ANOMALY = 'behavior-anomaly',
  DEPENDENCY_CHAIN = 'dependency-chain',
  PERMISSION_ESCALATION = 'permission-escalation',
}

/** A single finding detected during a scan */
export interface Finding {
  /** Unique rule ID (e.g. "CE-001") */
  ruleId: string;
  /** Human-readable rule name */
  ruleName: string;
  /** Risk category */
  category: RuleCategory;
  /** Severity level */
  severity: Severity;
  /** File path where the issue was found (relative to scan root) */
  file: string;
  /** Line number (1-indexed), if applicable */
  line?: number;
  /** Column number (1-indexed), if applicable */
  column?: number;
  /** Description of what was found */
  description: string;
  /** The suspicious code or configuration snippet */
  evidence?: string;
  /** Remediation advice */
  remediation: string;
  /** Mapped CVE IDs, if any */
  cveIds?: string[];
  /** Mapped CWE ID, if any */
  cweId?: string;
  /** Reference URLs for the attack pattern / vulnerability */
  references?: string[];
}

/** The result of a full scan */
export interface ScanResult {
  /** Scan metadata */
  meta: ScanMeta;
  /** All findings */
  findings: Finding[];
  /** Summary statistics */
  summary: ScanSummary;
}

export interface ScanMeta {
  /** Scanner version */
  scannerVersion: string;
  /** Timestamp of scan start */
  startedAt: string;
  /** Timestamp of scan end */
  finishedAt: string;
  /** Target path scanned */
  targetPath: string;
  /** Total duration in milliseconds */
  durationMs: number;
  /** Total files analyzed */
  totalFiles: number;
}

export interface ScanSummary {
  /** Count by severity */
  bySeverity: Record<Severity, number>;
  /** Count by category */
  byCategory: Record<RuleCategory, number>;
  /** Total findings */
  totalFindings: number;
  /** Overall risk score (0-100, higher = more risky) */
  riskScore: number;
  /** Is this skill/MCP safe to install? */
  safeToInstall: boolean;
}

/** A detection rule definition */
export interface DetectionRule {
  /** Unique rule ID */
  id: string;
  /** Human-readable name */
  name: string;
  /** Risk category */
  category: RuleCategory;
  /** Default severity */
  severity: Severity;
  /** Description of what this rule detects */
  description: string;
  /** Remediation guidance */
  remediation: string;
  /** Mapped CWE ID */
  cweId?: string;
  /** Known CVE IDs related to this pattern */
  cveIds?: string[];
  /** Reference URLs */
  references?: string[];
  /** The actual detection function */
  check: (content: string, filePath: string) => Finding | Finding[] | null;
}

/** Parsed skill metadata */
export interface SkillInfo {
  name: string;
  description: string;
  version?: string;
  author?: string;
  license?: string;
  allowedTools?: string[];
  /** Raw frontmatter as key-value */
  frontmatter: Record<string, unknown>;
  /** The instruction body (after frontmatter) */
  instructions: string;
}

/** Parsed MCP server configuration */
export interface McpServerConfig {
  name: string;
  transport: 'stdio' | 'sse' | 'streamable-http';
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}

/** Parsed MCP configuration file */
export interface McpConfig {
  servers: McpServerConfig[];
  raw: Record<string, unknown>;
}

/** A file to be analyzed */
export interface ScannedFile {
  /** Relative path from scan root */
  path: string;
  /** File content */
  content: string;
  /** File extension */
  ext: string;
  /** File size in bytes */
  size: number;
}
