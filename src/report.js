import { riskLevel } from './scoring.js';

/**
 * 报告渲染：终端彩色文本 + --json 结构化输出。
 */

const COLORS = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  orange: '\x1b[38;5;208m',
  red: '\x1b[31m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  reset: '\x1b[0m',
};

const SEVERITY_SYMBOL = { high: '✗', medium: '⚠', low: '○' };
const SEVERITY_COLOR = { high: 'red', medium: 'yellow', low: 'dim' };
const LEVEL_COLOR = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'green',
};

function makePaint(useColor) {
  return (c, s) => (useColor && c ? `${COLORS[c]}${s}${COLORS.reset}` : s);
}

/** 渲染终端报告，返回字符串 */
export function renderReport(result, { useColor = true } = {}) {
  const { version, targets, filesCount, findings, scoreResult } = result;
  const rl = riskLevel(scoreResult.score);
  const paint = makePaint(useColor);
  const lines = [];

  lines.push(paint('bold', `SkillScan v${version} — npm audit for AI Agent Skills`));
  lines.push(paint('dim', '─'.repeat(56)));
  lines.push(`扫描目标: ${targets.join(', ')}`);
  lines.push(`文件数: ${filesCount}   命中: ${scoreResult.findingsCount}   命中规则: ${scoreResult.ruleCount}`);

  if (findings.length > 0) {
    const byFile = new Map();
    for (const f of findings) {
      if (!byFile.has(f.file)) byFile.set(f.file, { high: 0, medium: 0, low: 0 });
      byFile.get(f.file)[f.severity] = (byFile.get(f.file)[f.severity] ?? 0) + 1;
    }
    lines.push('');
    lines.push(paint('bold', '按文件分布:'));
    for (const [file, c] of byFile) {
      const parts = [];
      if (c.high) parts.push(paint('red', `${c.high} high`));
      if (c.medium) parts.push(paint('yellow', `${c.medium} medium`));
      if (c.low) parts.push(paint('dim', `${c.low} low`));
      lines.push(`  ${file}  →  ${parts.join(', ')}`);
    }
  }

  if (findings.length === 0) {
    lines.push('');
    lines.push(paint('green', '✓ 未发现危险模式'));
  } else {
    lines.push('');
    for (const f of findings) {
      const sym = SEVERITY_SYMBOL[f.severity] ?? '•';
      const c = paint(SEVERITY_COLOR[f.severity] ?? 'dim', sym);
      lines.push(`${c} [${f.severity}] ${f.name}`);
      lines.push(paint('dim', `    ${f.file}:${f.line}`));
      if (f.match) lines.push(paint('dim', `    ${truncate(f.match, 100)}`));
    }
  }

  lines.push('');
  lines.push(paint('dim', '─'.repeat(56)));
  const scoreColor = LEVEL_COLOR[rl.level];
  const scoreStr = paint(scoreColor, `${rl.symbol} ${scoreResult.score}/100 ${rl.label}`);
  lines.push(paint('bold', `风险评分: ${scoreStr}`));
  lines.push(paint('dim', '0-24 SAFE · 25-49 CAUTION · 50-74 HIGH · 75+ CRITICAL'));

  return lines.join('\n');
}

/** 渲染 JSON 输出（供 CI / 工具链消费） */
export function renderJson(result) {
  return JSON.stringify(
    {
      tool: 'skillscan',
      version: result.version,
      targets: result.targets,
      filesCount: result.filesCount,
      score: result.scoreResult.score,
      level: riskLevel(result.scoreResult.score).level,
      findingsCount: result.scoreResult.findingsCount,
      findings: result.findings,
    },
    null,
    2,
  );
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
