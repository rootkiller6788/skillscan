import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

/**
 * SkillScan 文件解析器。
 * 产出可供扫描的「行」列表：每个可执行/可疑上下文的一行文本 + 真实行号。
 */

const SCRIPT_EXTENSIONS = new Set([
  '.sh', '.bash', '.zsh', '.ksh',
  '.py', '.js', '.mjs', '.cjs',
  '.ps1', '.rb', '.pl', '.php', '.ts', '.lua',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn',
  'dist', 'build', 'coverage', '__pycache__',
  '.venv', 'venv', '.idea', '.vscode', '.next', '.turbo',
]);

// 明确标记为 shell 的代码块语言
const SHELLISH_LANG = new Set([
  'bash', 'sh', 'shell', 'zsh', 'ksh',
  'console', 'terminal', 'pwsh', 'powershell',
]);

const MAX_FILE_BYTES = 1024 * 1024; // 跳过 >1MB 文件

// 内联代码片段是否「像命令」
const INLINE_COMMANDISH =
  /^\s*(\$|#|>)?\s*(curl|wget|fetch|bash|sh|zsh|sudo|rm|npm|pnpm|yarn|pip|pip3|gem|cargo|git|echo|cat|chmod|chown|python|python3|node|powershell|pwsh|base64|nc|socat|tee|dd|install)\b/;

/** 解析一个 Skill 目录，返回扫描单元列表 */
export function parseSkillDir(dirPath) {
  const files = [];
  collectFiles(dirPath, dirPath, files);
  return files;
}

function collectFiles(root, current, out) {
  let entries;
  try {
    entries = readdirSync(current, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = join(current, entry.name);
    if (entry.isDirectory()) {
      collectFiles(root, full, out);
    } else if (entry.isFile() && isScanTarget(entry.name)) {
      let content;
      try {
        if (statSync(full).size > MAX_FILE_BYTES) continue;
        content = readFileSync(full, 'utf8');
      } catch {
        continue; // 二进制/不可读文件跳过
      }
      const relPath = toRel(root, full);
      out.push({ relPath, size: content.length, lines: extractLines(relPath, content) });
    }
  }
}

function isScanTarget(name) {
  const lower = name.toLowerCase();
  if (lower === 'skill.md') return true;
  const ext = extname(lower);
  if (SCRIPT_EXTENSIONS.has(ext)) return true;
  if (ext === '.md') {
    // 跳过 LICENSE / CHANGELOG 等非技能文档
    return lower !== 'license' && lower !== 'license.md' &&
      lower !== 'changelog' && lower !== 'changelog.md' && lower !== 'authors';
  }
  return false;
}

function toRel(root, full) {
  return full.slice(root.length).replace(/\\/g, '/').replace(/^\//, '');
}

/**
 * 从文件内容提取「可扫描行」。
 * - 脚本文件：全部行。
 * - Markdown：shell 代码块内的行 + 看起来像命令的内联代码片段。
 */
export function extractLines(relPath, content) {
  const isMd = /\.md$/i.test(relPath);
  const raw = content.split('\n');
  const out = [];

  if (!isMd) {
    raw.forEach((text, i) => out.push({ line: i + 1, text }));
    return out;
  }

  let i = 0;
  while (i < raw.length) {
    const fence = /^\s*(```|~~~)\s*([\w+-]*)/.exec(raw[i]);
    if (fence) {
      const lang = fence[2].toLowerCase();
      const isShellish = SHELLISH_LANG.has(lang) || lang === '';
      i++; // 跳过开 fence
      while (i < raw.length && !/^\s*(```|~~~)/.test(raw[i])) {
        if (isShellish) out.push({ line: i + 1, text: raw[i] });
        i++;
      }
      i++; // 跳过闭 fence
      continue;
    }

    // 行内代码片段：形如 `curl ...` / `sudo ...`
    const inline = /`([^`\n]+)`/.exec(raw[i]);
    if (inline && looksLikeCommand(inline[1])) {
      out.push({ line: i + 1, text: inline[1] });
    }
    i++;
  }
  return out;
}

function looksLikeCommand(code) {
  if (!code) return false;
  if (INLINE_COMMANDISH.test(code)) return true;
  if (/\|\s*(ba|z|k|fi)?sh\b/.test(code)) return true; // curl | bash
  if (/^\$\s*\(/.test(code)) return true; // $(...)
  return false;
}
