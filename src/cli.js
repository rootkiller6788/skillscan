import { readFileSync, statSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { parseSkillDir, extractLines } from './parser.js';
import { scanFiles } from './scanner.js';
import { scoreFindings } from './scoring.js';
import { renderReport, renderJson } from './report.js';

const VERSION = readJson('../package.json').version;
const DEFAULT_THRESHOLD = 50;

class ScanError extends Error {}

/**
 * CLI 入口。
 * 返回 exit code：0 = 通过，1 = 风险分超阈值，2 = 用法/扫描错误。
 */
export function run(argv, io = {}) {
  const out = io.out ?? ((s) => process.stdout.write(s + '\n'));
  const err = io.err ?? ((s) => process.stderr.write(s + '\n'));

  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    err(String(e.message ?? e));
    err(HELP);
    return 2;
  }

  if (opts.help) {
    out(HELP);
    return 0;
  }
  if (opts.version) {
    out(`skillscan v${VERSION}`);
    return 0;
  }

  const targets = opts.targets.length > 0 ? opts.targets : ['.'];

  const files = [];
  for (const t of targets) {
    try {
      files.push(...loadTarget(t));
    } catch (e) {
      if (e instanceof ScanError) {
        err(`✗ ${e.message}`);
        return 2;
      }
      throw e;
    }
  }

  const findings = scanFiles(files);
  const scoreResult = scoreFindings(findings);

  const result = {
    version: VERSION,
    targets,
    filesCount: files.length,
    findings,
    scoreResult,
  };

  // 注意：isTTY 在管道/非 TTY 下是 undefined，必须布尔化，
  // 否则 renderReport 的默认参数 `useColor = true` 会把它当 true。
  const autoColor = Boolean(process.stdout.isTTY || process.env.FORCE_COLOR);
  const useColor = autoColor && !opts.json && !opts.noColor && !process.env.NO_COLOR;

  if (opts.json) {
    out(renderJson(result));
  } else {
    out(renderReport(result, { useColor }));
  }

  return scoreResult.score >= opts.threshold ? 1 : 0;
}

function loadTarget(target) {
  const abs = resolve(target);
  let st;
  try {
    st = statSync(abs);
  } catch {
    throw new ScanError(`路径不存在: ${target}`);
  }

  if (st.isFile()) {
    const content = readFileSync(abs, 'utf8');
    const relPath = normalizeRel(target);
    return [{ relPath, size: content.length, lines: extractLines(relPath, content) }];
  }
  if (st.isDirectory()) {
    const files = parseSkillDir(abs);
    if (files.length === 0) {
      throw new ScanError(`目录中没有可扫描的技能文件: ${target}`);
    }
    return files;
  }
  throw new ScanError(`不支持的路径类型: ${target}`);
}

function normalizeRel(target) {
  let p = target.replace(/\\/g, '/');
  p = p.replace(/^\.\//, '').replace(/^\/+/, '');
  return p === '' ? basename(target) : p;
}

function parseArgs(argv) {
  const opts = {
    targets: [],
    json: false,
    noColor: false,
    help: false,
    version: false,
    threshold: DEFAULT_THRESHOLD,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') {
      opts.json = true;
    } else if (a === '--no-color') {
      opts.noColor = true;
    } else if (a === '-h' || a === '--help') {
      opts.help = true;
    } else if (a === '-v' || a === '--version') {
      opts.version = true;
    } else if (a === '--threshold') {
      if (i + 1 >= argv.length) throw new Error('--threshold 需要一个 0-100 的值');
      opts.threshold = parseThreshold(argv[++i]);
    } else if (a.startsWith('--threshold=')) {
      opts.threshold = parseThreshold(a.split('=')[1]);
    } else if (a.startsWith('-')) {
      throw new Error(`未知参数: ${a}`);
    } else {
      opts.targets.push(a);
    }
  }

  return opts;
}

function parseThreshold(s) {
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n > 100) {
    throw new Error(`无效的 --threshold 值: "${s}"（应为 0-100 的整数）`);
  }
  return n;
}

function readJson(rel) {
  return JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8'));
}

const HELP = `
skillscan — npm audit for AI Agent Skills

用法:
  skillscan [目录...] [选项]

参数:
  目录          要扫描的 Skill 目录（可多个），默认当前目录 "."
                （也支持直接扫描单个文件）

选项:
  --json               输出结构化 JSON（供 CI/工具链消费）
  --threshold <0-100>  风险分达到该值则 exit code = 1，默认 ${DEFAULT_THRESHOLD}
  --no-color           禁用颜色输出
  -h, --help           显示帮助
  -v, --version        显示版本

exit code:
  0  通过（风险分 < 阈值）
  1  未通过（风险分 ≥ 阈值）
  2  用法错误或路径不存在

示例:
  skillscan ./skills
  skillscan ./my-skill --json | jq .score
  skillscan ./my-skill --threshold 80
`;
