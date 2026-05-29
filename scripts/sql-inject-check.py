#!/usr/bin/env python3
"""
sql-inject-check.py — SQL 注入检测工具

识别未使用 ORM/参数化查询的 SQL 拼接代码。
支持 Python、JavaScript/Node.js、Java、PHP、Ruby、Go。

用法: python sql-inject-check.py <目录路径> [--output json|text] [--language python,js]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

# ============================================================
# SQL 操作关键字
# ============================================================
SQL_KEYWORDS = r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|INNER\s+JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|ON|GROUP\s+BY|ORDER\s+BY|HAVING|UNION|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|EXEC|EXECUTE)'

# ============================================================
# 检测规则 — 按语言分类
# ============================================================

DETECTION_RULES = {
    # ========== Python ==========
    "python": [
        {
            "name": "Python f-string SQL 拼接",
            "pattern": rf'(?:execute|cursor\.execute|db\.execute)\s*\(\s*f["\']\s*{SQL_KEYWORDS}',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "f-string 直接嵌入 SQL 查询",
        },
        {
            "name": "Python .format() SQL 拼接",
            "pattern": rf'(?:execute|cursor\.execute|db\.execute)\s*\(\s*["\'].*{SQL_KEYWORDS}.*["\']\.format\(',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": ".format() 方法拼接 SQL",
        },
        {
            "name": "Python % 格式化 SQL 拼接",
            "pattern": rf'(?:execute|cursor\.execute|db\.execute)\s*\(\s*["\'].*{SQL_KEYWORDS}.*["\']\s*%\s*[\(\w]',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "% 字符串格式化拼接 SQL",
        },
        {
            "name": "Python + 拼接 SQL",
            "pattern": rf'(?:execute|cursor\.execute|db\.execute)\s*\(\s*["\'].*{SQL_KEYWORDS}.*["\']\s*\+',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "+ 运算符拼接 SQL",
        },
        {
            "name": "Python 字符串拼接 SQL（变量）",
            "pattern": rf'(?:execute|cursor\.execute|db\.execute)\s*\(\s*\w+\s*\+',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "变量直接拼接到 SQL",
        },
        {
            "name": "Python ORM raw() 危险调用",
            "pattern": r'\.raw\s*\(\s*f["\']',
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "Django ORM raw() 使用 f-string",
        },
        {
            "name": "Python ORM extra() 调用",
            "pattern": r'\.extra\s*\(',
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "Django ORM extra() 可能存在 SQL 注入",
        },
        {
            "name": "Python SQLAlchemy text() 拼接",
            "pattern": r'text\s*\(\s*f["\']',
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "SQLAlchemy text() 使用 f-string",
        },
        {
            "name": "Python sqlite3 拼接",
            "pattern": r'execute\s*\(\s*f["\'].*(?:INSERT|UPDATE|DELETE|SELECT)',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "sqlite3 直接拼接 SQL",
        },
    ],

    # ========== JavaScript/Node.js ==========
    "javascript": [
        {
            "name": "JS 模板字符串 SQL 拼接",
            "pattern": rf'(?:query|execute|run)\s*\(\s*`[^`]*{SQL_KEYWORDS}',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "模板字面量直接嵌入 SQL",
        },
        {
            "name": "JS + 拼接 SQL",
            "pattern": rf'(?:query|execute|run)\s*\(\s*["\'].*{SQL_KEYWORDS}.*["\']\s*\+',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "+ 运算符拼接 SQL",
        },
        {
            "name": "JS Knex raw() 拼接",
            "pattern": r'\.raw\s*\(\s*`[^`]*\$\{',
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "Knex raw() 模板字面量注入",
        },
        {
            "name": "Sequelize query 拼接",
            "pattern": r'se queryInterface\.\w+\(\s*[`"\']',
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "Sequelize queryInterface 可能存在注入",
        },
        {
            "name": "MongoDB $where 注入",
            "pattern": r'\$where\s*:',
            "severity": "HIGH",
            "cwe": "CWE-943",
            "description": "MongoDB $where 直接执行 JS 代码",
        },
        {
            "name": "Node.js child_process 命令注入",
            "pattern": r'child_process\.exec\s*\(\s*`?\s*\$\{|child_process\.exec\s*\(\s*["\']?\s*\+',
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "description": "child_process.exec 拼接用户输入",
        },
    ],

    # ========== Java ==========
    "java": [
        {
            "name": "Java + 拼接 SQL",
            "pattern": rf'(?:executeQuery|executeUpdate|execute)\s*\(\s*["\'].*{SQL_KEYWORDS}.*["\']\s*\+',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "Statement 直接拼接 SQL",
        },
        {
            "name": "Java String.format SQL",
            "pattern": rf'(?:executeQuery|executeUpdate|execute)\s*\(\s*String\.format\s*\(\s*["\'].*{SQL_KEYWORDS}',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "String.format 拼接 SQL",
        },
        {
            "name": "Java Runtime.exec",
            "pattern": r'Runtime\.getRuntime\(\)\.exec\s*\(',
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "description": "Runtime.exec 命令注入",
        },
        {
            "name": "Java ProcessBuilder shell",
            "pattern": r'new\s+ProcessBuilder\s*\(.*"sh".*"-c"',
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "description": "ProcessBuilder 通过 shell 执行命令",
        },
        {
            "name": "Java LDAP 注入",
            "pattern": r'(?:searchFilter|SearchFilter)\s*(?:=|:)\s*["\'].*\+',
            "severity": "HIGH",
            "cwe": "CWE-90",
            "description": "LDAP 过滤器拼接用户输入",
        },
        {
            "name": "Java XPath 注入",
            "pattern": r'(?:XPath|xpath|XPATH)\s*\.\s*(?:evaluate|compile)\s*\(.*\+',
            "severity": "HIGH",
            "cwe": "CWE-91",
            "description": "XPath 表达式拼接用户输入",
        },
    ],

    # ========== PHP ==========
    "php": [
        {
            "name": "PHP . 拼接 SQL",
            "pattern": rf'(?:mysqli_query|pg_query|sqlite_query)\s*\(.*\$\w+.*(?:{SQL_KEYWORDS})',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "PHP 函数拼接 SQL 变量",
        },
        {
            "name": "PHP 变量拼接 SQL",
            "pattern": rf'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\.\s*\$\w+',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "字符串连接符 . 拼接 SQL",
        },
        {
            "name": "PHP exec/system 命令注入",
            "pattern": r'\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$',
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "description": "命令执行函数拼接变量",
        },
        {
            "name": "PHP unserialize",
            "pattern": r'unserialize\s*\(\s*\$',
            "severity": "CRITICAL",
            "cwe": "CWE-502",
            "description": "反序列化不可信数据",
        },
        {
            "name": "PHP 文件包含",
            "pattern": r'(?:include|require|include_once|require_once)\s*\(\s*\$',
            "severity": "HIGH",
            "cwe": "CWE-98",
            "description": "文件包含使用变量路径",
        },
    ],

    # ========== Ruby ==========
    "ruby": [
        {
            "name": "Ruby 字符串插值 SQL",
            "pattern": rf'(?:execute|select_all|select_one|exec_query)\s*\(\s*["\'].*{SQL_KEYWORDS}.*#\{{',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "Ruby 字符串插值拼接 SQL",
        },
        {
            "name": "Ruby #{变量} SQL",
            "pattern": r'(?:WHERE|FROM|SELECT)\s+.*#\{?\w+\}?',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "#{variable} 直接嵌入 SQL",
        },
        {
            "name": "Ruby system/exec",
            "pattern": r'\b(?:system|exec|`)\s*\(?\s*\$\w+',
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "description": "命令执行拼接变量",
        },
    ],

    # ========== Go ==========
    "go": [
        {
            "name": "Go fmt.Sprintf SQL",
            "pattern": rf'(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf\s*\(\s*["`].*{SQL_KEYWORDS}',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "fmt.Sprintf 拼接 SQL",
        },
        {
            "name": "Go + 拼接 SQL",
            "pattern": rf'(?:Query|Exec|QueryRow)\s*\(\s*["`].*{SQL_KEYWORDS}.*["`]\s*\+',
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "description": "+ 运算符拼接 SQL",
        },
        {
            "name": "Go exec.Command shell",
            "pattern": r'exec\.Command\s*\(\s*"sh".*"-c"',
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "description": "exec.Command 通过 shell 执行命令",
        },
        {
            "name": "Go InsecureSkipVerify",
            "pattern": r'InsecureSkipVerify\s*:\s*true',
            "severity": "HIGH",
            "cwe": "CWE-295",
            "description": "跳过 TLS 证书验证",
        },
    ],
}

# 文件扩展名到语言映射
EXT_LANG_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'javascript',
    '.tsx': 'javascript',
    '.mjs': 'javascript',
    '.java': 'java',
    '.php': 'php',
    '.rb': 'ruby',
    '.go': 'go',
}

# 排除目录
EXCLUDE_DIRS = {
    'node_modules', '.git', 'venv', '.venv', 'env', '__pycache__',
    '.tox', 'dist', 'build', '.mypy_cache', 'vendor', 'target'
}

# 安全模式白名单（匹配到这些说明使用了安全方法）
SAFE_PATTERNS = [
    r'parameterized', r'prepared', r'placeholders',
    r'cursor\.execute\s*\([^,]+,\s*[\(\[]',  # 参数化元组
    r'\?',  # 占位符
    r'%s',  # psycopg2 风格
    r'\$\d+',  # PostgreSQL 风格
    r':\w+',  # 命名参数
    r'bindParam', r'bindValue', r'bind_param',
]


def is_safe_usage(line: str, prev_lines: list[str]) -> bool:
    """检查是否使用了安全的参数化方式"""
    # 如果行本身包含安全模式
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    # 检查前几行是否有参数化信号
    for prev in prev_lines[-3:]:
        if re.search(r'prepare\s*\(', prev, re.IGNORECASE):
            return True
        if re.search(r'cursor\.execute\s*\([^,]+,\s*[\(\[]', prev):
            return True
    return False


def detect_language(filepath: str) -> Optional[str]:
    """根据文件扩展名检测语言"""
    ext = os.path.splitext(filepath)[1].lower()
    return EXT_LANG_MAP.get(ext)


def scan_file(filepath: str, target_languages: list[str] = None) -> list[dict]:
    """扫描单个文件"""
    findings = []
    lang = detect_language(filepath)
    if not lang:
        return findings
    if target_languages and lang not in target_languages:
        return findings

    rules = DETECTION_RULES.get(lang, [])

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception:
        return findings

    for rule in rules:
        for i, line in enumerate(lines):
            # 跳过注释行
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('--'):
                continue
            # 跳过测试文件中的已知模式
            if any(p in filepath.lower() for p in ['test_', '_test.', 'spec.', '__test__', 'mock']):
                continue

            if re.search(rule["pattern"], line, re.IGNORECASE):
                prev_lines = lines[max(0, i-3):i]
                if not is_safe_usage(line, prev_lines):
                    findings.append({
                        'file': filepath,
                        'line': i + 1,
                        'type': rule["name"],
                        'severity': rule["severity"],
                        'cwe': rule["cwe"],
                        'description': rule["description"],
                        'code': line.strip()[:150],
                        'language': lang
                    })

    return findings


def scan_directory(root_dir: str, target_languages: list[str] = None) -> tuple[list[dict], int]:
    """递归扫描目录"""
    all_findings = []
    scanned = 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            ext = os.path.splitext(fname)[1].lower()
            if ext not in EXT_LANG_MAP:
                continue
            scanned += 1
            findings = scan_file(fpath, target_languages)
            all_findings.extend(findings)

    return all_findings, scanned


def main():
    parser = argparse.ArgumentParser(description='SQL 注入检测工具')
    parser.add_argument('directory', help='要扫描的项目目录')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='输出格式')
    parser.add_argument('--language', help='只扫描指定语言（逗号分隔: python,js,java,php,ruby,go）')
    parser.add_argument('--severity', default='critical,high',
                        help='只显示指定严重程度（逗号分隔）')
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[ERROR] 目录不存在: {args.directory}", file=sys.stderr)
        sys.exit(1)

    allowed_severities = set(s.strip().upper() for s in args.severity.split(','))
    target_langs = [l.strip().lower() for l in args.language.split(',')] if args.language else None

    findings, scanned = scan_directory(args.directory, target_langs)

    # 过滤严重程度
    findings = [f for f in findings if f['severity'] in allowed_severities]

    if args.output == 'json':
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        severity_icon = {
            'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'
        }
        print(f"\n{'='*60}")
        print(f"  SQL 注入/命令注入检测报告 — {args.directory}")
        print(f"{'='*60}\n")
        print(f"  扫描文件数: {scanned}")
        print(f"  发现问题数: {len(findings)}\n")

        if not findings:
            print("✅ 未发现 SQL 注入或命令注入风险\n")
        else:
            for f in findings:
                icon = severity_icon.get(f['severity'], '⚪')
                print(f"{icon} [{f['severity']}] {f['type']}")
                print(f"   文件: {f['file']}:{f['line']}")
                print(f"   CWE: {f['cwe']}")
                print(f"   描述: {f['description']}")
                print(f"   代码: {f['code']}")
                print()

            print(f"--- 修复建议 ---\n")
            print("  SQL 注入: 使用参数化查询（prepared statement）")
            print("    Python: cursor.execute('SELECT ... WHERE id = %s', (id,))")
            print("    JS:     db.query('SELECT ... WHERE id = $1', [id])")
            print("    Java:   PreparedStatement + setString()")
            print()
            print("  命令注入: 避免 shell=True，使用参数列表")
            print("    Python: subprocess.run(['cmd', 'arg1', 'arg2'])")
            print("    JS:     child_process.execFile('cmd', ['arg1'])")
            print()

        print(f"{'='*60}")

    sys.exit(1 if any(f['severity'] == 'CRITICAL' for f in findings) else 0)


if __name__ == '__main__':
    main()
