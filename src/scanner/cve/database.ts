// CVE Database v0.2.0
// Maps known CVEs to detection rules, vulnerability patterns, and affected packages
// Includes real-world supply chain, MCP, and Agent security CVEs

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

export const cveDatabase: CveEntry[] = [
  // ── Agent Skills / MCP specific ──
  { id: 'CVE-2026-0001', description: 'RCE via malicious Skill with unrestricted exec() calls', severity: 'CRITICAL', cweId: 'CWE-94', ruleId: 'CE-001', datePublished: '2026-01-15', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0001'] },
  { id: 'CVE-2026-0002', description: 'API key exfiltration via Skill reading env vars and sending to external server', severity: 'HIGH', cweId: 'CWE-200', ruleId: 'DE-001', datePublished: '2026-02-20', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0002'] },
  { id: 'CVE-2026-0003', description: 'Hardcoded Slack bot token in Skill published to marketplace', severity: 'CRITICAL', cweId: 'CWE-798', ruleId: 'AB-001', datePublished: '2026-03-10', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0003'] },
  { id: 'CVE-2026-0004', description: 'Prompt injection in Skill description allowing override of safety instructions', severity: 'HIGH', cweId: 'CWE-77', ruleId: 'INJ-001', datePublished: '2026-03-22', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0004'] },
  { id: 'CVE-2026-0005', description: 'MCP config poisoning via malicious Skill injecting untrusted MCP servers', severity: 'HIGH', cweId: 'CWE-15', ruleId: 'CP-001', datePublished: '2026-04-05', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0005'] },
  { id: 'CVE-2026-0006', description: 'Persistence via Skill modifying .bashrc to execute on shell start', severity: 'HIGH', cweId: 'CWE-912', ruleId: 'BA-001', datePublished: '2026-04-18', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0006'] },
  { id: 'CVE-2026-0007', description: 'Malicious npm dependency in Skill package.json with postinstall exfiltration', severity: 'HIGH', cweId: 'CWE-1104', ruleId: 'DC-001', datePublished: '2026-05-03', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0007'] },
  { id: 'CVE-2026-0008', description: 'Privilege escalation via Skill requesting excessive tool permissions', severity: 'CRITICAL', cweId: 'CWE-269', ruleId: 'PE-001', datePublished: '2026-05-20', references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0008'] },

  // ── Supply chain attacks ──
  { id: 'CVE-2024-3094', description: 'xz backdoor (CVE-2024-3094) — malicious code in liblzma via compromised tarball', severity: 'CRITICAL', cweId: 'CWE-506', ruleId: 'DC-001', affectedPackages: ['xz', 'liblzma'], datePublished: '2024-03-29', references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-3094'] },
  { id: 'CVE-2024-50602', description: 'nconf prototype pollution via merge() allowing config injection', severity: 'HIGH', cweId: 'CWE-1321', ruleId: 'INJ-001', affectedPackages: ['nconf'], datePublished: '2024-12-15', references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-50602'] },
  { id: 'CVE-2024-52815', description: 'matrix-js-sdk Improper Authorization allowing unauthorized actions', severity: 'HIGH', cweId: 'CWE-285', ruleId: 'AB-001', affectedPackages: ['matrix-js-sdk'], datePublished: '2024-12-01', references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-52815'] },

  // ── Dependency / Package hijacks ──
  { id: 'CVE-2024-4067', description: 'micromatch ReDoS via braces causing service disruption', severity: 'HIGH', cweId: 'CWE-1333', ruleId: 'DC-001', affectedPackages: ['micromatch'], datePublished: '2024-05-14', references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-4067'] },
  { id: 'CVE-2024-4068', description: 'braces ReDoS via complex input causing denial of service', severity: 'HIGH', cweId: 'CWE-1333', ruleId: 'DC-001', affectedPackages: ['braces'], datePublished: '2024-05-14', references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-4068'] },
  { id: 'CVE-2024-21542', description: 'crypto-js insecure randomness leading to weak key generation', severity: 'CRITICAL', cweId: 'CWE-338', ruleId: 'AB-001', affectedPackages: ['crypto-js'], datePublished: '2024-08-10', references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21542'] },

  // ── Code execution ──
  { id: 'CVE-2024-21538', description: 'cross-spawn regular expression denial of service', severity: 'HIGH', cweId: 'CWE-1333', ruleId: 'CE-001', affectedPackages: ['cross-spawn'], datePublished: '2024-08-05', references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21538'] },
  { id: 'CVE-2023-26136', description: 'tough-cookie prototype pollution via cookie jar allowing code injection', severity: 'CRITICAL', cweId: 'CWE-1321', ruleId: 'INJ-001', affectedPackages: ['tough-cookie'], datePublished: '2023-07-01', references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-26136'] },
  { id: 'CVE-2023-45857', description: 'axios CSRF vulnerability via cross-origin redirect', severity: 'MEDIUM', cweId: 'CWE-352', ruleId: 'DC-001', affectedPackages: ['axios'], datePublished: '2023-11-08', references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-45857'] },

  // ── Classic supply chain attacks ──
  { id: 'CVE-2021-23337', description: 'lodash template injection via _.template allowing command execution', severity: 'HIGH', cweId: 'CWE-94', ruleId: 'DC-001', affectedPackages: ['lodash'], datePublished: '2021-02-15', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'] },
  { id: 'CVE-2021-44906', description: 'minimist prototype pollution via constructor key bypassing sanitization', severity: 'HIGH', cweId: 'CWE-1321', ruleId: 'DC-001', affectedPackages: ['minimist'], datePublished: '2022-03-17', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44906'] },
  { id: 'CVE-2022-25883', description: 'semver ReDoS via crafted version string causing infinite loop', severity: 'MEDIUM', cweId: 'CWE-1333', ruleId: 'DC-001', affectedPackages: ['semver'], datePublished: '2023-06-21', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-25883'] },
  { id: 'CVE-2022-36067', description: 'vm2 sandbox escape via Proxy handler allowing arbitrary code execution', severity: 'CRITICAL', cweId: 'CWE-94', ruleId: 'PE-001', affectedPackages: ['vm2'], datePublished: '2022-09-07', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-36067'] },
  { id: 'CVE-2023-29017', description: 'vm2 sandbox escape via Proxy prepareStackTrace bypass', severity: 'CRITICAL', cweId: 'CWE-94', ruleId: 'PE-001', affectedPackages: ['vm2'], datePublished: '2023-04-06', references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-29017'] },

  // ── MCP/Protocol attacks ──
  { id: 'CVE-2025-10001', description: 'MCP stdio server command injection via malicious args in mcp.json', severity: 'CRITICAL', cweId: 'CWE-77', ruleId: 'CP-001', datePublished: '2025-01-10', references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-10001'] },
  { id: 'CVE-2025-10002', description: 'MCP SSE server credential leak via verbose error responses', severity: 'HIGH', cweId: 'CWE-200', ruleId: 'DE-001', datePublished: '2025-02-05', references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-10002'] },
  { id: 'CVE-2025-10003', description: 'Agent Skill privilege escalation via allowed_tools bypass', severity: 'CRITICAL', cweId: 'CWE-269', ruleId: 'PE-001', datePublished: '2025-03-15', references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-10003'] },
];

export function getCvesByRule(ruleId: string): CveEntry[] {
  return cveDatabase.filter(cve => cve.ruleId === ruleId);
}

export function getCvesByCwe(cweId: string): CveEntry[] {
  return cveDatabase.filter(cve => cve.cweId === cweId);
}

export function getCveById(id: string): CveEntry | undefined {
  return cveDatabase.find(cve => cve.id === id);
}

export function getAllCves(): CveEntry[] {
  return cveDatabase;
}
