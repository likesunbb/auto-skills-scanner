// MCP Config Parser
// Parses mcp.json configuration files and validates MCP server definitions
import * as fs from 'fs';
import * as path from 'path';
import { McpConfig, McpServerConfig } from '../../types';

/** Parse an mcp.json file and extract server configurations */
export function parseMcpConfig(filePath: string): McpConfig | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const raw = JSON.parse(content);
    return parseMcpConfigFromObject(raw, filePath);
  } catch {
    return null;
  }
}

/** Parse MCP config from a parsed JSON object */
function parseMcpConfigFromObject(raw: Record<string, unknown>, _filePath: string): McpConfig {
  const servers: McpServerConfig[] = [];

  const mcpServers = raw.mcpServers || raw.mcp_servers || raw.servers || {};
  
  if (typeof mcpServers === 'object' && mcpServers !== null) {
    for (const [name, config] of Object.entries(mcpServers as Record<string, unknown>)) {
      if (typeof config === 'object' && config !== null) {
        const cfg = config as Record<string, unknown>;
        const server: McpServerConfig = {
          name,
          transport: (cfg.transport as McpServerConfig['transport']) || 'stdio',
          url: cfg.url as string | undefined,
          command: cfg.command as string | undefined,
          args: cfg.args as string[] | undefined,
          env: cfg.env as Record<string, string> | undefined,
        };
        servers.push(server);
      }
    }
  }

  return { servers, raw };
}

/** Find mcp.json files in a directory tree */
export function findMcpConfigs(dirPath: string): string[] {
  const configs: string[] = [];
  
  // Look for mcp.json at root, in .mcp/, .config/mcp/
  const candidates = [
    path.join(dirPath, 'mcp.json'),
    path.join(dirPath, '.mcp.json'),
    path.join(dirPath, '.mcp', 'config.json'),
    path.join(dirPath, '.config', 'mcp.json'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      configs.push(candidate);
    }
  }

  return configs;
}

/** Validate a single MCP server configuration for security issues */
export interface McpServerValidation {
  name: string;
  issues: Array<{
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    issue: string;
    recommendation: string;
  }>;
}

export function validateMcpServer(server: McpServerConfig): McpServerValidation {
  const issues: McpServerValidation['issues'] = [];

  // Check transport security
  if (server.transport === 'sse' || server.transport === 'streamable-http') {
    if (server.url) {
      if (server.url.startsWith('http://')) {
        issues.push({
          severity: 'HIGH',
          issue: 'Remote MCP server using unencrypted HTTP',
          recommendation: 'Use HTTPS for all remote MCP connections',
        });
      }
      // Check for raw IP addresses
      if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(server.url)) {
        issues.push({
          severity: 'MEDIUM',
          issue: 'MCP server connecting to raw IP address',
          recommendation: 'Use domain names with HTTPS to ensure server identity',
        });
      }
      // Check for suspicious ports
      if (/:\d{1,4}$/.test(server.url)) {
        const port = parseInt(server.url.split(':').pop()!, 10);
        if (port < 1024 && port !== 443 && port !== 80) {
          issues.push({
            severity: 'LOW',
            issue: `MCP server using non-standard port ${port}`,
            recommendation: 'Verify this is an intentional configuration',
          });
        }
      }
    } else {
      issues.push({
        severity: 'HIGH',
        issue: 'Remote MCP server has no URL configured',
        recommendation: 'Specify the server URL for remote transports',
      });
    }
  }

  // Check stdio transport
  if (server.transport === 'stdio') {
    if (server.command) {
      const cmd = server.command.toLowerCase();
      // Check for dangerous commands
      if (['bash', 'sh', 'cmd', 'powershell', 'curl', 'wget'].includes(cmd)) {
        issues.push({
          severity: 'CRITICAL',
          issue: `MCP server using shell/interpreter as command: ${server.command}`,
          recommendation: 'Use the actual binary, not a shell wrapper',
        });
      }
      // Check npx with remote packages
      if (cmd === 'npx' && server.args) {
        const npxArgs = server.args.join(' ');
        if (npxArgs.includes('-y')) {
          issues.push({
            severity: 'HIGH',
            issue: 'MCP server uses npx -y (auto-install remote package)',
            recommendation: 'Verify the package source. Consider installing locally first.',
          });
        }
      }
    } else {
      issues.push({
        severity: 'HIGH',
        issue: 'STDIO MCP server has no command configured',
        recommendation: 'Specify the command to run the MCP server',
      });
    }
  }

  // Check for auth when remote
  if ((server.transport === 'sse' || server.transport === 'streamable-http') && !server.env) {
    issues.push({
      severity: 'MEDIUM',
      issue: 'Remote MCP server has no environment variables (possibly missing auth headers)',
      recommendation: 'Add authentication headers via env configuration',
    });
  }

  return { name: server.name, issues };
}
