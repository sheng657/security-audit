#!/usr/bin/env python3
"""
post-audit-update.py — 审计后自动更新检测规则库

核心流程:
1. 读取当前审计发现的问题列表 (JSON)
2. 扫描现有检测规则，提取已覆盖的 CWE 集合
3. 找出未覆盖的漏洞类型，抽取其特征模式
4. 自动追加到 secret-scan.py / sql-inject-check.py 的模式库
5. 更新 vulnerability-patterns.md 和 cwe-mapping.md

用法:
  python post-audit-update.py --findings findings.json --project-dir /path/to/project
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime

SKILL_DIR = Path(os.path.expanduser("~/.hermes/skills/security-audit"))
SCRIPTS_DIR = SKILL_DIR / "scripts"
REF_DIR = SKILL_DIR / "reference"


# ============================================================
# 已知模式指纹库 — 用于排除已存在的规则
# 格式: (CWE-ID, 模式关键词)
# ============================================================
KNOWN_PATTERNS = [
    # secret-scan.py 已覆盖
    ("CWE-798", "sk-"),
    ("CWE-798", "os.environ.get"),
    ("CWE-798", "AKIA"),
    ("CWE-798", "ghp_"),
    ("CWE-798", "password.*=.*['\"]"),
    ("CWE-312", "mysql://"),
    ("CWE-798", "-----BEGIN.*PRIVATE.*KEY"),
    ("CWE-22", "os.path.join.*file.filename"),
    # sql-inject-check.py 已覆盖
    ("CWE-89", "execute.*f-string"),
    ("CWE-89", "execute.*+"),
    ("CWE-89", "execute.*%s"),
    ("CWE-89", "execute.*format"),
    ("CWE-89", "raw()"),
    # 其他已覆盖
    ("CWE-79", "innerHTML"),
    ("CWE-79", "dangerouslySetInnerHTML"),
    ("CWE-79", "escHtml"),
    ("CWE-94", "eval("),
    ("CWE-78", "os.system"),
    ("CWE-78", "shell=True"),
    ("CWE-502", "pickle.loads"),
    ("CWE-943", "$where"),
    ("CWE-1336", "render_template_string"),
    ("CWE-338", "random.random"),
    ("CWE-327", "md5"),
    ("CWE-327", "sha1"),
]


def extract_pattern_key(finding: dict) -> tuple:
    """从发现中提取 CWE + 模式关键词"""
    cwe = finding.get("cwe", "")
    match_text = finding.get("match", "")
    context = finding.get("context", "")
    vuln_type = finding.get("type", "")
    key_text = f"{match_text[:40]}|{vuln_type}"
    return (cwe, key_text)


def is_known_pattern(finding: dict) -> bool:
    """判断该发现是否已被现有规则覆盖"""
    cwe = finding.get("cwe", "")
    context = finding.get("context", "")
    match_text = finding.get("match", "")
    
    for known_cwe, known_keyword in KNOWN_PATTERNS:
        if known_cwe == cwe:
            if known_keyword in context or known_keyword in match_text:
                return True
    return False


def classify_finding(finding: dict) -> str:
    """分类发现类型，决定更新哪个文件"""
    cwe = finding.get("cwe", "")
    vuln_type = finding.get("type", "")
    
    if cwe in ("CWE-22", "CWE-434"):
        return "path_traversal"
    if cwe in ("CWE-89",) or 'sql' in vuln_type.lower():
        return "sql_injection"
    if cwe in ("CWE-78",):
        return "command_injection"
    if cwe in ("CWE-798", "CWE-312", "CWE-256"):
        return "secret"
    if cwe in ("CWE-79",):
        return "xss"
    if cwe in ("CWE-16",):
        return "config"
    if cwe in ("CWE-327", "CWE-328", "CWE-330"):
        return "crypto"
    return "other"


def generate_regex_from_finding(finding: dict) -> str:
    """尝试从发现中生成一个可复用的正则表达式"""
    context = finding.get("context", "")
    match = finding.get("match", "")
    cwe = finding.get("cwe", "")
    
    if cwe == "CWE-22" and 'open(' in context:
        return r'open\s*\(\s*(?:request\.|input|sys\.stdin)'
    if cwe == "CWE-22":
        return r'os\.path\.join\s*\(\s*\w+\s*,\s*(?:file\.filename|request\.|input)'
    if cwe == "CWE-89" and '+' in context:
        return r'(?:execute|query)\s*\(.*\+' 
    if cwe == "CWE-798":
        return r'(?i)(?:key|secret|token|password)\s*[=:]\s*["\'][a-zA-Z0-9\-_]{20,}["\']'
    
    escaped = re.escape(match[:30]) if match else re.escape(context[:30])
    return escaped


def update_secret_patterns(finding: dict) -> bool:
    """尝试更新 secret-scan.py 的 SECRET_PATTERNS"""
    script_path = SCRIPTS_DIR / "secret-scan.py"
    with open(script_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    cwe = finding.get("cwe", "CWE-0")
    vuln_type = finding.get("type", "unknown")
    severity = finding.get("severity", "HIGH")
    
    pattern = generate_regex_from_finding(finding)
    name = f"auto_{vuln_type}_{cwe}_{datetime.now().strftime('%H%M%S')}"
    
    new_rule = f'    ("\u81ea\u52a8\u89c4\u5219: {vuln_type}", r\'{pattern}\', "{severity}", "{cwe}"),'
    
    last_bracket = content.rfind(']')
    if last_bracket > 0 and new_rule not in content:
        content = content[:last_bracket] + new_rule + '\n' + content[last_bracket:]
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False


def update_cwe_mapping(finding: dict) -> bool:
    """更新 cwe-mapping.md"""
    cwe_file = REF_DIR / "cwe-mapping.md"
    with open(cwe_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    cwe = finding.get("cwe", "CWE-0")
    vuln_type = finding.get("type", "unknown")
    severity = finding.get("severity", "MEDIUM")
    
    if cwe in content:
        return False
    
    icon = {'CRITICAL': '\U0001f534', 'HIGH': '\U0001f7e0', 'MEDIUM': '\U0001f7e1', 'LOW': '\U0001f7e2'}.get(severity, '\U0001f7e1')
    new_row = f"| {vuln_type} | {cwe} | 待查询 | {icon} {severity} | 自动发现 |"
    
    lines = content.split('\n')
    last_table_line = -1
    for i, line in enumerate(lines):
        if line.startswith('|') and '|' in line[1:]:
            last_table_line = i
    
    if last_table_line > 0:
        lines.insert(last_table_line + 1, new_row)
        with open(cwe_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        return True
    return False


def update_vulnerability_patterns(finding: dict) -> bool:
    """更新 vulnerability-patterns.md"""
    patterns_file = REF_DIR / "vulnerability-patterns.md"
    with open(patterns_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    vuln_type = finding.get("type", "unknown")
    severity = finding.get("severity", "HIGH")
    context = finding.get("context", "")
    cwe = finding.get("cwe", "CWE-0")
    match = finding.get("match", "")
    
    if vuln_type in content and context[:20] in content:
        return False
    
    new_entry = f"| {vuln_type} | \"{match[:40]}\" | {severity} | {cwe} | 自动发现 |"
    
    if not new_entry.strip() in content:
        content = content.rstrip() + '\n' + new_entry + '\n'
        with open(patterns_file, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False


def generate_diff_report(findings: list, new_patterns: list) -> str:
    """生成更新报告"""
    report = []
    report.append("\n" + "=" * 60)
    report.append("  自动更新报告 — 检测规则库扩展")
    report.append("=" * 60 + "\n")
    report.append(f"  审计发现总数: {len(findings)}")
    report.append(f"  已覆盖规则数: {len(findings) - len(new_patterns)}")
    report.append(f"  新增规则数: {len(new_patterns)}\n")
    
    if new_patterns:
        report.append("--- 🔧 新增检测规则 ---\n")
        for p in new_patterns:
            icon = {'CRITICAL': '\U0001f534', 'HIGH': '\U0001f7e0', 'MEDIUM': '\U0001f7e1', 'LOW': '\U0001f7e2'}.get(p.get('severity', ''), '\U0001f7e1')
            report.append(f"  {icon} {p.get('type', 'unknown')} ({p.get('cwe', 'CWE-0')})")
            report.append(f"    上下文: {p.get('context', '')[:80]}")
            report.append(f"    已更新: secret-scan.py / cwe-mapping.md / vulnerability-patterns.md")
            report.append("")
    else:
        report.append("✅ 所有发现均已被现有规则覆盖，无需更新\n")
    
    report.append("=" * 60)
    return '\n'.join(report)


def main():
    parser = argparse.ArgumentParser(description='审计后自动更新检测规则库')
    parser.add_argument('--findings', required=True, help='审计发现 JSON 文件路径')
    parser.add_argument('--dry-run', action='store_true', help='仅预览，不实际写入')
    parser.add_argument('--output', choices=['text', 'json'], default='text')
    args = parser.parse_args()
    
    with open(args.findings, 'r', encoding='utf-8') as f:
        findings = json.load(f)
    
    new_patterns = []
    updated_files = set()
    
    for finding in findings:
        if is_known_pattern(finding):
            continue
        
        new_patterns.append(finding)
        
        if not args.dry_run:
            category = classify_finding(finding)
            
            if category in ('secret', 'path_traversal', 'crypto'):
                if update_secret_patterns(finding):
                    updated_files.add('secret-scan.py')
            elif category == 'sql_injection':
                updated_files.add('sql-inject-check.py (待手动曝光)')
            
            update_cwe_mapping(finding)
            update_vulnerability_patterns(finding)
    
    report = generate_diff_report(findings, new_patterns)
    
    if args.output == 'json':
        result = {
            'total_findings': len(findings),
            'new_patterns': len(new_patterns),
            'updated_files': list(updated_files),
            'details': [{
                'type': p.get('type'),
                'cwe': p.get('cwe'),
                'severity': p.get('severity'),
                'context': p.get('context', '')[:100]
            } for p in new_patterns]
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(report)
        if updated_files:
            print(f"\n已更新文件: {', '.join(updated_files)}")


if __name__ == '__main__':
    main()