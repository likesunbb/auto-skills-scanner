// Skill.md Parser
// Parses frontmatter (YAML/TOML) and instruction body from Skill definition files
import * as fs from 'fs';
import * as path from 'path';
import { SkillInfo, ScannedFile } from '../../types';

/** Parse a Skill.md file and extract metadata + instructions */
export function parseSkillMd(filePath: string): SkillInfo | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return parseSkillContent(content, filePath);
  } catch {
    return null;
  }
}

/** Parse skill content from a string */
function parseSkillContent(content: string, filePath: string): SkillInfo {
  const frontmatter: Record<string, unknown> = {};
  let instructions = content;
  let name = path.basename(path.dirname(filePath)) || 'unknown';
  let description = '';

  // Try YAML frontmatter (--- ... ---)
  const yamlMatch = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n/);
  if (yamlMatch) {
    const yamlContent = yamlMatch[1];
    instructions = content.slice(yamlMatch[0].length);

    // Simple YAML parser for common frontmatter fields
    const lines = yamlContent.split('\n');
    for (const line of lines) {
      const kvMatch = line.match(/^(\w[\w_-]*)\s*:\s*(.+)$/);
      if (kvMatch) {
        const key = kvMatch[1].trim();
        let value: unknown = kvMatch[2].trim();
        // Remove quotes
        if (typeof value === 'string' && (value.startsWith('"') || value.startsWith("'"))) {
          value = value.slice(1, -1);
        }
        // Parse arrays: [a, b, c]
        if (typeof value === 'string' && value.startsWith('[') && value.endsWith(']')) {
          value = value.slice(1, -1).split(',').map(v => v.trim().replace(/^["']|["']$/g, ''));
        }
        frontmatter[key] = value;
      }
    }

    name = (frontmatter.name as string) || name;
    description = (frontmatter.description as string) || '';
  }

  // Try TOML frontmatter (+++ ... +++)
  const tomlMatch = content.match(/^\+\+\+\s*\n([\s\S]*?)\n\+\+\+\s*\n/);
  if (tomlMatch && !yamlMatch) {
    const tomlContent = tomlMatch[1];
    instructions = content.slice(tomlMatch[0].length);

    const lines = tomlContent.split('\n');
    for (const line of lines) {
      const kvMatch = line.match(/^(\w[\w_-]*)\s*=\s*(.+)$/);
      if (kvMatch) {
        const key = kvMatch[1].trim();
        let value: unknown = kvMatch[2].trim();
        if (typeof value === 'string') {
          value = value.replace(/^["']|["']$/g, '');
          if (value === 'true') value = true;
          else if (value === 'false') value = false;
        }
        frontmatter[key] = value;
      }
    }

    if (!name || name === 'unknown') {
      name = (frontmatter.name as string) || name;
    }
    if (!description) {
      description = (frontmatter.description as string) || '';
    }
  }

  // Extract description from first heading if not in frontmatter
  if (!description) {
    const headingMatch = instructions.match(/^#\s+(.+)$/m);
    if (headingMatch) {
      description = headingMatch[1].trim();
    }
  }

  // Extract allowedTools from frontmatter or instructions
  let allowedTools: string[] | undefined;
  if (Array.isArray(frontmatter.allowed_tools)) {
    allowedTools = frontmatter.allowed_tools as string[];
  }

  return {
    name,
    description,
    version: frontmatter.version as string | undefined,
    author: frontmatter.author as string | undefined,
    license: frontmatter.license as string | undefined,
    allowedTools,
    frontmatter,
    instructions: instructions.trim(),
  };
}

/** Scan a skill directory and collect all files for analysis */
export function scanSkillDirectory(dirPath: string): ScannedFile[] {
  const files: ScannedFile[] = [];
  const walkDir = (dir: string) => {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // Skip node_modules, .git, __pycache__
        if (['node_modules', '.git', '__pycache__', '.venv', 'venv', 'dist', '.cache'].includes(entry.name)) {
          continue;
        }
        walkDir(fullPath);
      } else if (entry.isFile()) {
        // Read text files, skip binaries
        const ext = path.extname(entry.name).toLowerCase();
        const textExts = ['.md', '.json', '.ts', '.js', '.py', '.yaml', '.yml', '.toml', '.sh', '.ps1', '.txt', '.cfg', '.ini', '.env'];
        if (textExts.includes(ext) || entry.name === 'Dockerfile' || entry.name === 'Makefile') {
          try {
            const content = fs.readFileSync(fullPath, 'utf-8');
            const stat = fs.statSync(fullPath);
            files.push({
              path: path.relative(dirPath, fullPath),
              content,
              ext,
              size: stat.size,
            });
          } catch {
            // Skip files that can't be read as text
          }
        }
      }
    }
  };

  walkDir(dirPath);
  return files;
}
