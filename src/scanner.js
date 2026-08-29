import { RULES, EXFIL_SENSITIVE, EXFIL_SEND, EXFIL_WINDOW, severityRank } from './rules.js';

/**
 * 扫描器：对每个解析文件逐行跑规则，产出 findings。
 * 外泄（exfil）是文件级检测：敏感读取 + 网络发送出现在同一文件近邻行。
 */

const EXFIL_RULE = RULES.find((r) => r.id === 'exfil');

export function scanFiles(files) {
  const findings = [];

  for (const file of files) {
    const seen = new Set();

    for (const { line, text } of file.lines) {
      for (const rule of RULES) {
        if (rule.id === 'exfil') continue; // 文件级处理
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(text)) {
          const key = rule.id + ':' + line;
          if (seen.has(key)) continue; // 同一行同规则只记一次
          seen.add(key);
          findings.push({
            ruleId: rule.id,
            name: rule.name,
            category: rule.category,
            severity: rule.severity,
            description: rule.description,
            file: file.relPath,
            line,
            match: extractMatch(text, rule.pattern),
          });
        }
      }
    }

    const exfil = detectExfil(file);
    if (exfil && EXFIL_RULE) {
      findings.push({
        ruleId: EXFIL_RULE.id,
        name: EXFIL_RULE.name,
        category: EXFIL_RULE.category,
        severity: EXFIL_RULE.severity,
        description: EXFIL_RULE.description,
        file: file.relPath,
        line: exfil.line,
        match: exfil.text.trim().slice(0, 140),
      });
    }
  }

  return findings.sort(compareFindings);
}

function extractMatch(text, pattern) {
  pattern.lastIndex = 0;
  const m = text.match(pattern);
  return m ? m[0].trim().slice(0, 140) : '';
}

function compareFindings(a, b) {
  const s = severityRank(a.severity) - severityRank(b.severity);
  if (s !== 0) return s;
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  return a.line - b.line;
}

/** 文件级疑似外泄检测：敏感读取与网络发送在近邻行内同时出现 */
export function detectExfil(file) {
  const sens = [];
  const send = [];

  for (const { line, text } of file.lines) {
    if (EXFIL_SENSITIVE.test(text)) sens.push({ line, text });
    if (EXFIL_SEND.test(text)) send.push({ line, text });
  }

  let best = null;
  for (const s of sens) {
    for (const e of send) {
      const dist = Math.abs(s.line - e.line);
      if (best === null || dist < best.dist) {
        best = { dist, line: e.line, text: e.text };
      }
    }
  }

  return best && best.dist <= EXFIL_WINDOW ? best : null;
}
