# Contributing to AUTO Skills Scanner

Thanks for helping secure the Agent ecosystem!

## Adding Detection Rules

1. Create a new file in `src/scanner/rules/` named after the category (e.g. `crypto-mining.ts`)
2. Implement the `DetectionRule` interface
3. Add the rule to `src/scanner/rules/index.ts` `allRules` array
4. Add a CVE entry in `src/scanner/cve/database.ts`
5. Add a test fixture in `test-fixtures/`

### Rule Template

```typescript
import { DetectionRule, Finding, RuleCategory, Severity } from '../../types';

export const myRule: DetectionRule = {
  id: 'XX-001',
  name: 'My Rule Name',
  category: RuleCategory.CODE_EXECUTION,
  severity: Severity.CRITICAL,
  description: 'What this rule detects',
  remediation: 'How to fix it',
  cweId: 'CWE-XXX',
  cveIds: ['CVE-YYYY-NNNNN'],
  references: ['https://...'],
  check(content: string, filePath: string): Finding[] {
    // Pattern matching logic
    const findings: Finding[] = [];
    // ... detection logic ...
    return findings;
  },
};
```

## Adding CVEs

Add entries to `src/scanner/cve/database.ts`:

```typescript
{
  id: 'CVE-YYYY-NNNNN',
  description: 'One-line description',
  severity: 'CRITICAL', // CRITICAL | HIGH | MEDIUM | LOW
  cweId: 'CWE-XXX',
  ruleId: 'XX-001',     // which rule this CVE maps to
  affectedPackages: ['package-name'],
  datePublished: 'YYYY-MM-DD',
  references: ['https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN'],
}
```

## Development

```bash
git clone https://github.com/likesunbb/auto-skills-scanner.git
cd auto-skills-scanner
npm install
npm run build        # compile TypeScript
node dist/cli.js scan ./test-fixtures/malicious-skill/
```

## Testing

```bash
# Should return CRITICAL findings (exit code 1)
node dist/cli.js scan ./test-fixtures/malicious-skill/ --json

# Should return 0 findings (exit code 0)
node dist/cli.js scan ./test-fixtures/safe-skill/ --json

# Should detect MCP config issues
node dist/cli.js scan ./test-fixtures/mcp-server/ --json
```

## Pull Requests

1. Add/update rules → include test fixture
2. Bug fixes → add regression test
3. Always run `npm run build` before committing

## License

MIT — contributions are licensed under the same terms.
