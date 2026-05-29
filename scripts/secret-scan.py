#!/usr/bin/env python3
"""
secret-scan.py — 硬编码密钥/密码检测工具

使用正则模式扫描代码中的硬编码密钥、Token、密码、连接串等敏感信息。

用法: python secret-scan.py <目录路径> [--output json|text] [--exclude <模式>]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

# ============================================================
# 敏感信息正则模式库
# 格式: (名称, 正则, 严重程度, CWE-ID)
# ============================================================
SECRET_PATTERNS = [
    # ---- AWS ----
    ("AWS Access Key", r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])', "CRITICAL", "CWE-798"),
    ("AWS Secret Key", r'(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "CRITICAL", "CWE-798"),
    ("AWS MWS Key", r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "CRITICAL", "CWE-798"),

    # ---- GitHub ----
    ("GitHub Token", r'ghp_[A-Za-z0-9]{36}', "CRITICAL", "CWE-798"),
    ("GitHub OAuth", r'gho_[A-Za-z0-9]{36}', "CRITICAL", "CWE-798"),
    ("GitHub Fine-grained", r'github_pat_[A-Za-z0-9_]{82}', "CRITICAL", "CWE-798"),
    ("GitHub App Token", r'(ghu|ghs)_[A-Za-z0-9]{36}', "CRITICAL", "CWE-798"),

    # ---- GitLab ----
    ("GitLab Token", r'glpat-[A-Za-z0-9\-_]{20,}', "CRITICAL", "CWE-798"),
    ("GitLab Pipeline Token", r'glptt-[A-Za-z0-9\-_]{20,}', "CRITICAL", "CWE-798"),

    # ---- Slack ----
    ("Slack Token", r'xox[baprs]-[0-9]{10,}(-[a-zA-Z0-9]+)*', "CRITICAL", "CWE-798"),
    ("Slack Webhook", r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+', "HIGH", "CWE-798"),
    ("通用 API Key (sk-前缀)", r'(?<![A-Za-z0-9])sk-[a-f0-9]{32}(?![a-Za-z0-9])', "CRITICAL", "CWE-798"),

    # ---- Google ----
    ("Google API Key", r'AIza[0-9A-Za-z\-_]{35}', "HIGH", "CWE-798"),
    ("Google OAuth", r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "HIGH", "CWE-798"),

    # ---- Azure ----
    ("Azure Storage Account Key", r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}', "CRITICAL", "CWE-798"),

    # ---- 通用密钥/密码 ----
    ("硬编码密码（变量赋值）", r'(?i)(password|passwd|pwd|secret|token|api_key|apikey|api_secret|access_key|auth_token|private_key)\s*[=:]\s*["\']([^"\']{6,})["\']', "HIGH", "CWE-798"),
    ("硬编码密码（JSON 字段）", r'(?i)"(password|secret|token|api_key|access_key|private_key)"\s*:\s*"([^"]{6,})"', "HIGH", "CWE-798"),

    # ---- 数据库连接串 ----
    ("数据库连接串（含密码）", r'(?i)(mysql|postgres|postgresql|mongodb|redis|amqp|mssql)://[^:]+:[^@]+@[^\s"\']+', "HIGH", "CWE-312"),
    ("JDBC 连接串", r'jdbc:[a-z]+://[^\s"\']+password=[^\s"&]+', "HIGH", "CWE-312"),

    # ---- 私钥 ----
    ("RSA 私钥", r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "CRITICAL", "CWE-798"),
    ("DSA 私钥", r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----', "CRITICAL", "CWE-798"),
    ("EC 私钥", r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----', "CRITICAL", "CWE-798"),

    # ---- JWT ----
    ("JWT 密钥硬编码", r'(?i)(jwt[_\-]?(?:secret|key)|JWT[_\-]?(?:SECRET|KEY))\s*[=:]\s*["\']([^"\']{8,})["\']', "HIGH", "CWE-798"),
    ("JWT 在代码中", r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+', "MEDIUM", "CWE-798"),

    # ---- npm / PyPI / NuGet ----
    ("npm Token", r'npm_[A-Za-z0-9]{36}', "CRITICAL", "CWE-798"),
    ("PyPI Token", r'pypi-[A-Za-z0-9\-_]{50,}', "CRITICAL", "CWE-798"),

    # ---- Twilio ----
    ("Twilio API Key", r'SK[0-9a-fA-F]{32}', "HIGH", "CWE-798"),
    ("Twilio Account SID", r'AC[0-9a-fA-F]{32}', "MEDIUM", "CWE-798"),

    # ---- Stripe ----
    ("Stripe Secret Key", r'sk_live_[0-9a-zA-Z]{24,}', "CRITICAL", "CWE-798"),
    ("Stripe Publishable Key", r'pk_live_[0-9a-zA-Z]{24,}', "MEDIUM", "CWE-798"),

    # ---- SendGrid ----
    ("SendGrid API Key", r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}', "CRITICAL", "CWE-798"),

    # ---- Telegram ----
    ("Telegram Bot Token", r'[0-9]{9}:[A-Za-z0-9_\-]{35}', "HIGH", "CWE-798"),

    # ---- 微信 ----
    ("微信 AppSecret", r'(?i)(app_?secret|wx_?secret|wechat_?secret)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?', "HIGH", "CWE-798"),

    # ---- 阿里云 ----
    ("阿里云 AccessKey", r'LTAI[0-9A-Za-z]{12,20}', "CRITICAL", "CWE-798"),
]

# 需要排除的文件/目录
EXCLUDE_DIRS = {
    'node_modules', '.git', 'venv', '.venv', 'env', '__pycache__',
    '.tox', 'dist', 'build', '.mypy_cache', '.idea', '.vscode',
    'vendor', '.terraform', 'target', 'coverage'
}

EXCLUDE_FILES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Pipfile.lock',
    'poetry.lock', 'go.sum', 'Cargo.lock', '.DS_Store'
}


def should_exclude(filepath: str, extra_excludes: list[str] = None) -> bool:
    """判断文件是否应被排除"""
    parts = Path(filepath).parts
    for part in parts:
        if part in EXCLUDE_DIRS:
            return True
    basename = os.path.basename(filepath)
    if basename in EXCLUDE_FILES:
        return True
    if extra_excludes:
        for pattern in extra_excludes:
            if pattern in filepath:
                return True
    # 跳过二进制文件的常见扩展名
    binary_ext = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
                  '.woff', '.woff2', '.ttf', '.eot', '.otf',
                  '.mp3', '.mp4', '.wav', '.avi',
                  '.zip', '.tar', '.gz', '.rar', '.7z',
                  '.exe', '.dll', '.so', '.dylib', '.class',
                  '.pdf', '.doc', '.docx', '.xls', '.xlsx'}
    ext = os.path.splitext(basename)[1].lower()
    if ext in binary_ext:
        return True
    return False


def is_likely_false_positive(line: str, match: str, context: str) -> bool:
    """过滤常见误报"""
    stripped = line.strip()

    # 注释中的示例/文档
    if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
        doc_keywords = ['example', 'sample', 'placeholder', 'your_', 'xxx',
                        '示例', '示', 'example.com', 'changeme', 'TODO', 'FIXME']
        for kw in doc_keywords:
            if kw.lower() in line.lower():
                return True

    # 测试文件中的 mock 值
    if any(p in context.lower() for p in ['test_', '_test.', 'spec.', 'mock', 'fixture', 'fake']):
        return True

    # 空/占位符值
    placeholder_values = {
        'password', 'passwd', 'secret', 'changeme', 'xxx', 'yyy',
        'your_password', 'your_secret', 'your_key', 'test',
        'example', 'placeholder', '<password>', '{password}',
        '${password}', '${secret}', '${api_key}', '${token}',
        'REPLACE_ME', 'TODO', 'FILL_IN',
    }
    if match.lower() in placeholder_values:
        return True
    # 包含占位符模板变量
    if '${' in match or '{{' in match or '<' in match:
        return True

    # 测试用固定 Token（如 eyJ... 开头的测试 JWT）
    if match.startswith('eyJ') and 'test' in context.lower():
        return True

    return False


def scan_file(filepath: str, extra_excludes: list[str] = None) -> list[dict]:
    """扫描单个文件"""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_num, line in enumerate(lines, 1):
        for name, pattern, severity, cwe in SECRET_PATTERNS:
            matches = re.finditer(pattern, line)
            for m in matches:
                matched_text = m.group(0)
                # 如果是分组匹配，取最后一个非空组作为值
                if m.lastindex:
                    matched_text = m.group(m.lastindex)

                if is_likely_false_positive(line, matched_text, filepath):
                    continue

                findings.append({
                    'file': filepath,
                    'line': line_num,
                    'type': name,
                    'severity': severity,
                    'cwe': cwe,
                    'match': matched_text[:80] + ('...' if len(matched_text) > 80 else ''),
                    'context': line.strip()[:120]
                })

    return findings


def scan_directory(root_dir: str, extra_excludes: list[str] = None) -> list[dict]:
    """递归扫描目录"""
    all_findings = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 就地修改 dirnames 以跳过排除目录
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if should_exclude(fpath, extra_excludes):
                continue
            scanned += 1
            findings = scan_file(fpath, extra_excludes)
            all_findings.extend(findings)

    return all_findings, scanned


def main():
    parser = argparse.ArgumentParser(description='硬编码密钥/密码检测工具')
    parser.add_argument('directory', help='要扫描的项目目录')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='输出格式')
    parser.add_argument('--exclude', action='append', default=[], help='额外排除的路径模式')
    parser.add_argument('--severity', default='critical,high,medium,low',
                        help='只显示指定严重程度（逗号分隔）')
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[ERROR] 目录不存在: {args.directory}", file=sys.stderr)
        sys.exit(1)

    allowed_severities = set(s.strip().upper() for s in args.severity.split(','))

    findings, scanned = scan_directory(args.directory, args.exclude)

    # 过滤严重程度
    findings = [f for f in findings if f['severity'] in allowed_severities]

    # 去重
    seen = set()
    unique = []
    for f in findings:
        key = (f['file'], f['line'], f['type'])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    if args.output == 'json':
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        severity_icon = {
            'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'
        }
        print(f"\n{'='*60}")
        print(f"  硬编码密钥扫描报告 — {args.directory}")
        print(f"{'='*60}\n")
        print(f"  扫描文件数: {scanned}")
        print(f"  发现问题数: {len(findings)}\n")

        if not findings:
            print("✅ 未发现硬编码密钥\n")
        else:
            # 按严重程度分组
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                sev_findings = [f for f in findings if f['severity'] == sev]
                if not sev_findings:
                    continue
                icon = severity_icon[sev]
                print(f"\n--- {icon} {sev} ({len(sev_findings)}) ---\n")
                for f in sev_findings:
                    print(f"  {f['file']}:{f['line']}")
                    print(f"    类型: {f['type']} ({f['cwe']})")
                    print(f"    匹配: {f['match']}")
                    print(f"    上下文: {f['context']}")
                    print()

        print(f"{'='*60}")

    sys.exit(1 if any(f['severity'] == 'CRITICAL' for f in findings) else 0)


if __name__ == '__main__':
    main()
