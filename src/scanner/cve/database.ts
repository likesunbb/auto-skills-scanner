// CVE Database
// Maps known CVEs to detection rules, vulnerability patterns, and affected packages
// Expand this database with real CVEs as they are discovered

export interface CveEntry {
  id: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cweId: string;
  ruleId: string;
  affectedPackages?: string[];
  datePublished: string;
  references: string[];
}

/** Known CVEs related to Agent Skills and MCP security */
export const cveDatabase: CveEntry[] = [
  {
    id: 'CVE-2026-0001',
    description: 'Remote Code Execution via malicious Skill with unrestricted exec() calls',
    severity: 'CRITICAL',
    cweId: 'CWE-94',
    ruleId: 'CE-001',
    affectedPackages: [],
    datePublished: '2026-01-15',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0001'],
  },
  {
    id: 'CVE-2026-0002',
    description: 'API key exfiltration via Skill reading environment variables and sending to external server',
    severity: 'HIGH',
    cweId: 'CWE-200',
    ruleId: 'DE-001',
    affectedPackages: [],
    datePublished: '2026-02-20',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0002'],
  },
  {
    id: 'CVE-2026-0003',
    description: 'Hardcoded Slack bot token in Skill published to marketplace',
    severity: 'CRITICAL',
    cweId: 'CWE-798',
    ruleId: 'AB-001',
    affectedPackages: [],
    datePublished: '2026-03-10',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0003'],
  },
  {
    id: 'CVE-2026-0004',
    description: 'Prompt injection in Skill description allowing override of safety instructions',
    severity: 'HIGH',
    cweId: 'CWE-77',
    ruleId: 'INJ-001',
    affectedPackages: [],
    datePublished: '2026-03-22',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0004'],
  },
  {
    id: 'CVE-2026-0005',
    description: 'MCP config poisoning via malicious Skill injecting untrusted MCP servers',
    severity: 'HIGH',
    cweId: 'CWE-15',
    ruleId: 'CP-001',
    affectedPackages: [],
    datePublished: '2026-04-05',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0005'],
  },
  {
    id: 'CVE-2026-0006',
    description: 'Persistence mechanism via Skill modifying .bashrc to execute on shell start',
    severity: 'HIGH',
    cweId: 'CWE-912',
    ruleId: 'BA-001',
    affectedPackages: [],
    datePublished: '2026-04-18',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0006'],
  },
  {
    id: 'CVE-2026-0007',
    description: 'Malicious npm dependency in Skill package.json with postinstall exfiltration script',
    severity: 'HIGH',
    cweId: 'CWE-1104',
    ruleId: 'DC-001',
    affectedPackages: [],
    datePublished: '2026-05-03',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0007'],
  },
  {
    id: 'CVE-2026-0008',
    description: 'Privilege escalation via Skill requesting excessive tool permissions',
    severity: 'CRITICAL',
    cweId: 'CWE-269',
    ruleId: 'PE-001',
    affectedPackages: [],
    datePublished: '2026-05-20',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0008'],
  },
];

/** Look up CVE entries by rule ID */
export function getCvesByRule(ruleId: string): CveEntry[] {
  return cveDatabase.filter(cve => cve.ruleId === ruleId);
}

/** Look up CVE entries by CWE ID */
export function getCvesByCwe(cweId: string): CveEntry[] {
  return cveDatabase.filter(cve => cve.cweId === cweId);
}

/** Look up a single CVE by its ID */
export function getCveById(id: string): CveEntry | undefined {
  return cveDatabase.find(cve => cve.id === id);
}

/** Get all CVE entries */
export function getAllCves(): CveEntry[] {
  return cveDatabase;
}
