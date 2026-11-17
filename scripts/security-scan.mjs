#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DISPLAY_LIMIT = 200;

const rules = [
  {
    id: 'reverse-shell',
    description: 'Common reverse-shell or shell-over-network construct',
    pattern: /(?:\/dev\/tcp\/|nc\s+-e\b|ncat\s+.*--exec\b|bash\s+-i\b.*(?:\/dev\/tcp|>&)|\b(?:TcpClient|Socket)\b.{0,160}\b(?:Process|Start-Process|exec)\b)/i,
  },
  {
    id: 'download-and-execute',
    description: 'A downloader and command interpreter appear on the same line',
    pattern: /(?:curl|wget|Invoke-WebRequest|iwr|Start-BitsTransfer).{0,240}(?:\|\s*(?:bash|sh|pwsh|powershell)|(?:bash|sh|pwsh|powershell|node|python)\s+-c\b)|(?:bash|sh|pwsh|powershell|node|python)\s+-c\b.{0,240}(?:https?:\/\/|curl|wget|Invoke-WebRequest)/i,
  },
  {
    id: 'encoded-command',
    description: 'Encoded PowerShell command or base64-to-dynamic-code pattern',
    pattern: /(?:powershell(?:\.exe)?\b.{0,100}-(?:e|enc|encodedcommand)\b|(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\s*\()/i,
  },
  {
    id: 'dynamic-code',
    description: 'Dynamic JavaScript code evaluation',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(/i,
  },
  {
    id: 'process-execution',
    description: 'Process or shell execution API / command',
    pattern: /(?:child_process|Deno\.Command|Bun\.spawn|shell\s*:\s*true|execSync\s*\(|spawnSync\s*\(|\b(?:cmd(?:\.exe)?\s+\/c|powershell(?:\.exe)?\s+-Command|sh\s+-c)\b)/i,
  },
  {
    id: 'persistence',
    description: 'Operating-system startup or scheduled-task persistence reference',
    pattern: /(?:CurrentVersion\\Run|schtasks(?:\.exe)?\s+\/create|crontab\s+-|\/etc\/cron\.|LaunchAgents|systemctl\s+enable|Startup\\)/i,
  },
  {
    id: 'secret-access',
    description: 'Credential, token, or private-key access reference',
    pattern: /(?:process\.env\.(?:PASSWORD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)|(?:id_rsa|\.ssh\/|credential(?:s)?\s*[:=]))/i,
  },
  {
    id: 'network-listener',
    description: 'Network server/listener creation reference',
    pattern: /(?:\b(?:https?|net|tls)\.createServer\s*\(|\.listen\s*\(\s*(?:\d{2,5}|0)\s*[,)]|\bTcpListener\b)/i,
  },
];

function parseArgs(args) {
  let root = DEFAULT_ROOT;
  let jsonPath;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--root' && args[index + 1]) {
      root = path.resolve(args[++index]);
    } else if (arg === '--json' && args[index + 1]) {
      jsonPath = path.resolve(args[++index]);
    } else if (arg === '--help' || arg === '-h') {
      console.log('Usage: node scripts/security-scan.mjs [--root DIRECTORY] [--json REPORT.json]');
      process.exit(0);
    } else {
      throw new Error(`Unknown or incomplete option: ${arg}`);
    }
  }

  return { root, jsonPath };
}

function scanFile(filePath, relativePath, results, errors) {
  let content;
  try {
    content = fs.readFileSync(filePath).toString('utf8');
  } catch (error) {
    errors.push({ file: relativePath, error: error.message });
    return;
  }

  const lines = content.split(/\r?\n/);
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    for (const rule of rules) {
      if (rule.pattern.test(line)) {
        results.push({
          rule: rule.id,
          description: rule.description,
          file: relativePath,
          line: lineIndex + 1,
          excerpt: line.trim().slice(0, 240),
        });
      }
    }
  }
}

function walk(directory, root, state) {
  let entries;
  try {
    entries = fs.readdirSync(directory, { withFileTypes: true });
  } catch (error) {
    state.errors.push({
      file: path.relative(root, directory) || '.',
      error: error.message,
    });
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    const relativePath = path.relative(root, fullPath).split(path.sep).join('/');
    if (entry.isSymbolicLink()) {
      state.symlinks.push(relativePath);
    } else if (entry.isDirectory()) {
      walk(fullPath, root, state);
    } else if (entry.isFile()) {
      state.fileCount += 1;
      scanFile(fullPath, relativePath, state.matches, state.errors);
    }
  }
}

function main() {
  const { root, jsonPath } = parseArgs(process.argv.slice(2));
  if (!fs.statSync(root).isDirectory()) {
    throw new Error(`Scan root is not a directory: ${root}`);
  }

  const state = { fileCount: 0, matches: [], errors: [], symlinks: [] };
  walk(root, root, state);

  const report = {
    root,
    scannedAt: new Date().toISOString(),
    filesScanned: state.fileCount,
    symlinksNotFollowed: state.symlinks.length,
    readErrors: state.errors,
    rules: rules.map(({ id, description }) => ({ id, description })),
    matchCount: state.matches.length,
    matches: state.matches,
  };
  const countsByRule = new Map(rules.map(({ id }) => [id, 0]));
  for (const match of state.matches) {
    countsByRule.set(match.rule, countsByRule.get(match.rule) + 1);
  }

  console.log(`Static security indicator scan: ${root}`);
  console.log(`Regular files scanned: ${report.filesScanned}`);
  console.log(`Symbolic links not followed: ${report.symlinksNotFollowed}`);
  console.log(`Read errors: ${report.readErrors.length}`);
  console.log(`Indicator matches: ${report.matchCount}`);
  for (const [rule, count] of countsByRule) {
    if (count > 0) console.log(`  ${rule}: ${count}`);
  }

  const displayedMatches = state.matches.slice(0, DISPLAY_LIMIT);
  for (const match of displayedMatches) {
    console.log(`[${match.rule}] ${match.file}:${match.line}: ${match.excerpt}`);
  }
  if (state.matches.length > DISPLAY_LIMIT) {
    console.log(`... ${state.matches.length - DISPLAY_LIMIT} additional matches omitted from console output.`);
  }

  for (const error of state.errors) {
    console.error(`[read-error] ${error.file}: ${error.error}`);
  }
  if (jsonPath) {
    fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
    console.log(`Full report written to: ${jsonPath}`);
  }
  console.log('Matches are heuristic indicators, not proof of malicious behavior or proof the repository is clean.');
  if (state.errors.length > 0) process.exitCode = 2;
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 2;
}
