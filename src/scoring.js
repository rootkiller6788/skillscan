import { severityRank } from './rules.js';

/**
 * 加权计分：0–100。
 * 每条规则按严重度贡献权重（high=40 / medium=20 / low=10），
 * 同一规则命中多处只计一次（避免单文件刷爆分），累计后封顶 100。
 */

export const SEVERITY_WEIGHT = { high: 40, medium: 20, low: 10 };

export function scoreFindings(findings) {
  const byRule = new Map();

  for (const f of findings) {
    if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, []);
    byRule.get(f.ruleId).push(f);
  }

  let score = 0;
  const breakdown = [];
  for (const [ruleId, list] of byRule) {
    const weight = SEVERITY_WEIGHT[list[0].severity] ?? 10;
    breakdown.push({
      ruleId,
      name: list[0].name,
      severity: list[0].severity,
      count: list.length,
      weight,
    });
    score += weight;
  }

  return {
    score: Math.min(100, score),
    level: riskLevel(Math.min(100, score)).level,
    findingsCount: findings.length,
    ruleCount: breakdown.length,
    breakdown: breakdown.sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
  };
}

export function riskLevel(score) {
  if (score >= 75) {
    return { level: 'critical', label: 'CRITICAL', symbol: '✗' };
  }
  if (score >= 50) {
    return { level: 'high', label: 'HIGH RISK', symbol: '⚠' };
  }
  if (score >= 25) {
    return { level: 'medium', label: 'CAUTION', symbol: '⚠' };
  }
  return { level: 'low', label: 'SAFE', symbol: '✓' };
}
