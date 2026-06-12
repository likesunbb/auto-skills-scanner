// AI Analyzer — OpenAI-compatible API client for LLM-assisted scanning
// SECURITY: AI is DISABLED by default. User must explicitly configure an API.
// Note: MiMo free API (api.xiaomimimo.com) is no longer functional as of 2026-06-12.
// Use your own API key or a local model (Ollama recommended: http://localhost:11434/v1)
import * as https from 'https';
import * as http from 'http';
import { Finding, ScanResult } from '../types';

export interface AiConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
  enabled: boolean;
}

export const DEFAULT_AI_CONFIG: AiConfig = {
  baseUrl: '',
  apiKey: '',
  model: 'ollama',
  enabled: false,
};

interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface ChatResponse {
  choices: Array<{ message: { content: string } }>;
  usage?: { total_tokens: number };
}

/** Call an OpenAI-compatible chat completion API */
async function chat(
  config: AiConfig,
  messages: ChatMessage[],
  maxTokens: number = 1024,
): Promise<string | null> {
  if (!config.enabled) return null;

  const url = new URL(config.baseUrl);
  url.pathname = url.pathname.replace(/\/?$/, '/chat/completions');

  const body = JSON.stringify({
    model: config.model,
    messages,
    max_tokens: maxTokens,
    temperature: 0.3,
  });

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + config.apiKey,
  };

  return new Promise((resolve) => {
    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.request(
      url.href,
      {
        method: 'POST',
        headers,
        timeout: 30000,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
        res.on('end', () => {
          try {
            const json: ChatResponse = JSON.parse(data);
            const content = json.choices?.[0]?.message?.content;
            resolve(content || null);
          } catch {
            resolve(null);
          }
        });
      },
    );

    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

/** Analyze a single suspicious finding with AI context */
export async function analyzeFinding(
  config: AiConfig,
  finding: Finding,
  fileContent?: string,
): Promise<string | null> {
  const messages: ChatMessage[] = [
    {
      role: 'system',
      content: `You are an Agent Skills security auditor. Analyze the following finding from a security scan of an AI Agent Skill or MCP server configuration.

Provide a concise analysis (2-4 sentences) covering:
1. Whether this is a real threat or likely a false positive
2. The actual impact if exploited
3. A specific, actionable fix

Be direct and technical. Do NOT say "as an AI" or use disclaimers.`,
    },
    {
      role: 'user',
      content: `FINDING:
- Rule: ${finding.ruleName} (${finding.ruleId})
- Severity: ${finding.severity}
- Category: ${finding.category}
- File: ${finding.file}${finding.line ? ':' + finding.line : ''}
- Description: ${finding.description}${finding.evidence ? '\n- Evidence:\n```\n' + finding.evidence + '\n```' : ''}${finding.cweId ? '\n- CWE: ' + finding.cweId : ''}${finding.remediation ? '\n- Scanner suggestion: ' + finding.remediation : ''}${fileContent ? '\n\nFILE CONTENT (relevant snippet):\n```\n' + fileContent.slice(0, 3000) + '\n```' : ''}

Analyze this finding:`,
    },
  ];

  return chat(config, messages, 512);
}

/** Generate an executive summary of scan results using AI */
export async function generateAISummary(
  config: AiConfig,
  result: ScanResult,
): Promise<string | null> {
  const { summary } = result;
  const topFindings = result.findings
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 5);

  const findingsText = topFindings.map(f =>
    `- [${f.severity}] ${f.ruleName}: ${f.description} (${f.file}${f.line ? ':' + f.line : ''})`
  ).join('\n');

  const messages: ChatMessage[] = [
    {
      role: 'system',
      content: `You are an Agent Skills security auditor. Generate a concise executive summary of a security scan of an AI Agent Skill or MCP server.

Format your response as:
1. OVERALL RISK: One sentence (e.g. "This skill poses a HIGH risk due to...")
2. KEY FINDINGS: 2-3 bullet points of the most critical issues
3. RECOMMENDATION: One sentence on whether to install, with caveats

Be direct. No disclaimers. No "as an AI".`,
    },
    {
      role: 'user',
      content: `SCAN RESULTS:
- Risk Score: ${summary.riskScore}/100
- Safe to Install: ${summary.safeToInstall ? 'YES' : 'NO'}
- Total Findings: ${summary.totalFindings}
- Critical: ${summary.bySeverity.CRITICAL}
- High: ${summary.bySeverity.HIGH}
- Medium: ${summary.bySeverity.MEDIUM}
- Low: ${summary.bySeverity.LOW}

Top Findings:
${findingsText || '(none)'}

Target: ${result.meta.targetPath}

Generate the executive summary:`,
    },
  ];

  return chat(config, messages, 512);
}

/** Quick health check — test if the AI API is reachable */
export async function checkApiHealth(config: AiConfig): Promise<{ ok: boolean; model: string; error?: string }> {
  try {
    const response = await chat(config, [
      { role: 'user', content: 'Reply with just "OK".' },
    ], 10);
    if (response && response.includes('OK')) {
      return { ok: true, model: config.model };
    }
    return { ok: false, model: config.model, error: 'Unexpected response' };
  } catch (e) {
    return { ok: false, model: config.model, error: e instanceof Error ? e.message : String(e) };
  }
}
