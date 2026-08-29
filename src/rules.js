/**
 * SkillScan 第一版静态规则集。
 * 全部离线、无 AI：基于正则的模式匹配。
 *
 * 严重度权重：high=40 / medium=20 / low=10（见 scoring.js）。
 */

export const RULES = [
  {
    id: 'pipe-exec',
    name: '管道执行',
    category: 'execution',
    severity: 'high',
    description: 'curl/wget 等下载代码后经管道交给 shell 直接执行',
    pattern: /(curl|wget|fetch)\s+[^\n|]*(\|\s*[^\n|]*)*\|\s*(ba|z|k|fi)?sh\b/,
  },
  {
    id: 'sh-c-subshell',
    name: '子 shell 执行',
    category: 'execution',
    severity: 'high',
    description: 'sh -c "$(curl ...)" 从远程拉取并在子 shell 中执行',
    pattern: /(ba|z|k)?sh\s+-c\s+["']\s*\$\(/,
  },
  {
    id: 'sudo',
    name: 'sudo 提权',
    category: 'privilege',
    severity: 'medium',
    description: '使用 sudo 提权执行命令',
    pattern: /\bsudo\b/,
  },
  {
    id: 'rm-rf',
    name: '危险删除',
    category: 'destructive',
    severity: 'high',
    description: 'rm -rf / rm -fr 递归强制删除',
    pattern: /\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*[fF]\b|\brm\s+-[a-zA-Z]*[fF][a-zA-Z]*[rR]\b/,
  },
  {
    id: 'sensitive-ssh',
    name: '读取 SSH 密钥',
    category: 'data',
    severity: 'high',
    description: '读取 ~/.ssh 或 SSH 私钥（id_rsa / *.pem）',
    pattern: /(~\/)?\.ssh\b|\.ssh[\\\/]|id_rsa|id_ed25519|\.pem\b/,
  },
  {
    id: 'sensitive-aws',
    name: '读取 AWS 凭证',
    category: 'data',
    severity: 'high',
    description: '读取 ~/.aws 凭证或硬编码 access key',
    pattern: /~\/?\.aws\b|\.aws[\\\/]|aws_access_key_id|aws_secret_access_key/,
  },
  {
    id: 'sensitive-env',
    name: '读取 .env',
    category: 'data',
    severity: 'medium',
    description: '读取 .env 环境变量文件',
    pattern: /\.env\b/,
  },
  {
    id: 'sensitive-credentials',
    name: '读取凭据文件',
    category: 'data',
    severity: 'high',
    description: '读取 .git-credentials / .netrc / .gnupg 等凭据',
    pattern: /\.git-credentials|\.netrc|\.gnupg/,
  },
  {
    id: 'sensitive-shadow',
    name: '读取系统密码文件',
    category: 'data',
    severity: 'high',
    description: '读取 /etc/shadow 系统密码哈希',
    pattern: /\/etc\/shadow/,
  },
  {
    id: 'install-unknown',
    name: '安装第三方包',
    category: 'supply-chain',
    severity: 'medium',
    description: 'npm/pip/gem/cargo 安装第三方包（未校验来源）',
    pattern: /\b(npm|pnpm|yarn|pip|pip3|gem|cargo)\s+(i|install|add)\b/,
  },
  {
    id: 'obfuscation',
    name: '混淆命令',
    category: 'obfuscation',
    severity: 'high',
    description: 'base64 解码执行 / powershell -enc / eval / IEX 混淆',
    pattern: /base64\s+(-d|-D|--decode)|powershell\s+-enc|\beval\b|from64|atob\(|\bIEX\s*\(/,
  },
  {
    id: 'reverse-shell',
    name: '反弹 shell',
    category: 'exfiltration',
    severity: 'high',
    description: 'bash /dev/tcp 或 nc -e 反弹 shell',
    pattern: /\/dev\/tcp\/|nc\s+-e|socat/i,
  },
  {
    id: 'network-download',
    name: '网络下载/外联',
    category: 'network',
    severity: 'low',
    description: '执行网络下载或外联请求（curl/wget/fetch）',
    pattern: /\b(curl|wget|fetch)\b/,
  },
  {
    id: 'exfil',
    name: '疑似外泄',
    category: 'exfiltration',
    severity: 'high',
    description: '读取敏感文件后紧邻发送到外部（同文件近邻行）',
    pattern: /.?/s, // 占位：由 scanner 的文件级检测负责
  },
];

// —— 文件级「外泄」检测用的信号（不参与逐行规则） ——

// 敏感文件信号
export const EXFIL_SENSITIVE =
  /\.ssh\b|\.aws\b|\.env\b|\.pem\b|shadow|credentials|id_rsa|\.gnupg|\.netrc|\.pgpass|\.npmrc/i;

// 发送信号：把数据发往外部网络的写法
export const EXFIL_SEND =
  /\b(curl|wget)\b|requests\.(get|post|put|patch|delete)|urllib|http\.client|Invoke-WebRequest|Invoke-RestMethod|socat|\bnc\b/i;

// 近邻窗口：敏感行与发送行相距 ≤ EXFIL_WINDOW 行即判定疑似外泄
export const EXFIL_WINDOW = 3;

/** 按严重度排序：high → medium → low */
export function severityRank(severity) {
  return severity === 'high' ? 0 : severity === 'medium' ? 1 : 2;
}
