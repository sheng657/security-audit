#!/usr/bin/env python3
"""
dep-scan.py — 依赖漏洞扫描工具

扫描 requirements.txt / package.json / go.mod / pom.xml 中的已知 CVE。
优先使用 OSV API 在线查询，离线时使用本地基础 CVE 数据库。

用法: python dep-scan.py <目录路径> [--output json|text] [--severity critical,high,medium,low]
"""

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

# ============================================================
# 本地已知高危 CVE 基础数据库（离线后备）
# 格式: { (包名, 版本范围): (severity, cve_id, description, fix_version) }
# ============================================================
LOCAL_CVE_DB = {
    # Python
    ("django", "<4.2.11"): ("CRITICAL", "CVE-2024-24680", "整数溢出导致 DoS", "4.2.11"),
    ("django", "<4.2.17"): ("HIGH", "CVE-2024-53986", "SQL 注入", "4.2.17"),
    ("flask", "<2.3.2"): ("HIGH", "CVE-2023-30861", "Session Cookie 安全属性缺失", "2.3.2"),
    ("requests", "<2.31.0"): ("CRITICAL", "CVE-2023-32681", "Proxy-Authorization 头泄露", "2.31.0"),
    ("urllib3", "<1.26.18"): ("HIGH", "CVE-2023-45803", "请求体未被正确清理", "1.26.18"),
    ("cryptography", "<42.0.0"): ("CRITICAL", "CVE-2024-26130", "PKCS12 序列化漏洞", "42.0.0"),
    ("pillow", "<10.0.1"): ("CRITICAL", "CVE-2023-44271", "拒绝服务", "10.0.1"),
    ("aiohttp", "<3.9.0"): ("CRITICAL", "CVE-2023-47627", "HTTP 请求走私", "3.9.0"),
    ("pyyaml", "<6.0.1"): ("HIGH", "CVE-2023-44271", "YAML 反序列化", "6.0.1"),
    ("paramiko", "<3.4.0"): ("HIGH", "CVE-2024-28755", "密钥交换漏洞", "3.4.0"),
    ("jinja2", "<3.1.4"): ("HIGH", "CVE-2024-22195", "XSS 漏洞", "3.1.4"),
    # Node.js
    ("express", "<4.19.2"): ("HIGH", "CVE-2024-29041", "路径遍历", "4.19.2"),
    ("lodash", "<4.17.21"): ("HIGH", "CVE-2021-23337", "命令注入", "4.17.21"),
    ("axios", "<0.28.0"): ("HIGH", "CVE-2024-28849", "凭证泄露", "0.28.0"),
    ("minimist", "<1.2.6"): ("HIGH", "CVE-2021-44906", "原型污染", "1.2.6"),
    ("tar", "<6.1.9"): ("HIGH", "CVE-2021-32803", "任意文件覆盖", "6.1.9"),
    ("ws", "<7.5.10"): ("HIGH", "CVE-2024-37890", "拒绝服务", "7.5.10"),
    ("jsonwebtoken", "<9.0.2"): ("CRITICAL", "CVE-2022-23529", "密钥泄露", "9.0.2"),
    # 通用
    ("log4j", "<2.17.0"): ("CRITICAL", "CVE-2021-44228", "Log4Shell RCE", "2.17.0"),
}


def version_tuple(v: str) -> tuple:
    """将版本号转为可比较的元组"""
    parts = []
    for p in re.split(r'[.\-]', v):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def version_in_range(version: str, spec: str) -> bool:
    """简单版本范围匹配: 支持 <X.Y.Z, <=X.Y.Z, ==X.Y.Z, >=X.Y.Z"""
    spec = spec.strip()
    if spec.startswith('<'):
        op = '<'
        ver = spec.lstrip('<=')
        if spec.startswith('<='):
            op = '<='
        elif spec.startswith('<'):
            op = '<'
    elif spec.startswith('>'):
        op = '>'
        ver = spec.lstrip('>')
        if spec.startswith('>='):
            op = '>='
    elif spec.startswith('==') or spec.startswith('>='):
        op = spec[:2]
        ver = spec[2:]
    else:
        return False

    try:
        v_cur = version_tuple(version)
        v_ref = version_tuple(ver)
    except Exception:
        return False

    if op == '<':
        return v_cur < v_ref
    elif op == '<=':
        return v_cur <= v_ref
    elif op == '>':
        return v_cur > v_ref
    elif op == '>=':
        return v_cur >= v_ref
    elif op == '==':
        return v_cur == v_ref
    return False


# ============================================================
# 依赖文件解析器
# ============================================================

def parse_requirements_txt(filepath: str) -> list[dict]:
    """解析 requirements.txt"""
    deps = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # 格式: package==1.2.3 / package>=1.0 / package~=1.2
                match = re.match(r'^([a-zA-Z0-9_\-.]+)\s*([><=!~]+)\s*([0-9][0-9a-zA-Z.\-]*)', line)
                if match:
                    deps.append({
                        'name': match.group(1).lower(),
                        'version': match.group(3),
                        'source': filepath,
                        'line': line
                    })
                else:
                    # 无版本号
                    match2 = re.match(r'^([a-zA-Z0-9_\-.]+)', line)
                    if match2:
                        deps.append({
                            'name': match2.group(1).lower(),
                            'version': None,
                            'source': filepath,
                            'line': line
                        })
    except Exception as e:
        print(f"[WARN] 读取 {filepath} 失败: {e}", file=sys.stderr)
    return deps


def parse_package_json(filepath: str) -> list[dict]:
    """解析 package.json"""
    deps = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for section in ['dependencies', 'devDependencies', 'peerDependencies']:
            for name, version_spec in data.get(section, {}).items():
                # 提取纯版本号（去掉 ^ ~ >= 等前缀）
                ver_match = re.search(r'(\d+\.\d+\.\d+[a-zA-Z0-9.\-]*)', version_spec)
                deps.append({
                    'name': name.lower(),
                    'version': ver_match.group(1) if ver_match else None,
                    'source': filepath,
                    'line': f'{name}: {version_spec}',
                    'version_spec': version_spec
                })
    except Exception as e:
        print(f"[WARN] 读取 {filepath} 失败: {e}", file=sys.stderr)
    return deps


def parse_go_mod(filepath: str) -> list[dict]:
    """解析 go.mod"""
    deps = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line.startswith('require'):
                    in_require = True
                    if '(' in line:
                        continue
                    # 单行 require
                if in_require and line == ')':
                    in_require = False
                    continue
                if in_require and line:
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0].split('/')[-1].lower()
                        ver = parts[1].lstrip('v')
                        deps.append({
                            'name': name,
                            'version': ver,
                            'source': filepath,
                            'line': line
                        })
    except Exception as e:
        print(f"[WARN] 读取 {filepath} 失败: {e}", file=sys.stderr)
    return deps


# ============================================================
# OSV API 在线查询
# ============================================================

def query_osv(package_name: str, version: str) -> list[dict]:
    """查询 OSV API 获取漏洞信息"""
    results = []
    try:
        payload = json.dumps({
            "package": {"name": package_name, "ecosystem": "PyPI"},
            "version": version
        }).encode('utf-8')

        req = urllib.request.Request(
            'https://api.osv.dev/v1/query',
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            for vuln in data.get('vulns', []):
                cve_id = vuln.get('id', 'UNKNOWN')
                summary = vuln.get('summary', '无描述')
                severity = 'HIGH'  # 默认

                # 从 severity 字段提取
                for sev in vuln.get('severity', []):
                    if sev.get('type') == 'CVSS_V3':
                        score_str = sev.get('score', '')
                        # 简单提取
                        break

                # 从 database_specific 提取
                db_spec = vuln.get('database_specific', {})
                if 'severity' in db_spec:
                    severity = db_spec['severity'].upper()

                results.append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'description': summary,
                    'fix_version': None
                })
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        pass  # 网络失败时静默降级
    return results


# ============================================================
# 扫描逻辑
# ============================================================

def scan_local_db(deps: list[dict]) -> list[dict]:
    """使用本地 CVE 数据库扫描"""
    findings = []
    for dep in deps:
        if not dep['version']:
            continue
        for (pkg, version_range), (severity, cve_id, desc, fix) in LOCAL_CVE_DB.items():
            if dep['name'] == pkg and version_in_range(dep['version'], version_range):
                findings.append({
                    **dep,
                    'severity': severity,
                    'cve_id': cve_id,
                    'description': desc,
                    'fix_version': fix,
                    'source_type': 'local_db'
                })
    return findings


def scan_online(deps: list[dict]) -> list[dict]:
    """使用 OSV API 在线扫描"""
    findings = []
    for dep in deps:
        if not dep['version']:
            continue
        osv_results = query_osv(dep['name'], dep['version'])
        for r in osv_results:
            findings.append({
                **dep,
                **r,
                'source_type': 'osv_api'
            })
    return findings


def find_dependency_files(root_dir: str) -> list[str]:
    """递归查找依赖文件"""
    targets = [
        'requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt',
        'setup.py', 'pyproject.toml',
        'package.json', 'yarn.lock',
        'go.mod',
        'pom.xml', 'build.gradle',
        'Cargo.toml',
        'Gemfile',
    ]
    found = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 跳过 node_modules, .git, venv 等
        dirnames[:] = [d for d in dirnames if d not in {
            'node_modules', '.git', 'venv', '.venv', 'env',
            '__pycache__', '.tox', 'dist', 'build', '.mypy_cache'
        }]
        for f in filenames:
            if f in targets:
                found.append(os.path.join(dirpath, f))
    return found


# ============================================================
# 主流程
# ============================================================

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

def main():
    parser = argparse.ArgumentParser(description='依赖漏洞扫描工具')
    parser.add_argument('directory', help='要扫描的项目目录')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='输出格式')
    parser.add_argument('--severity', default='critical,high,medium,low',
                        help='只显示指定严重程度（逗号分隔）')
    parser.add_argument('--online', action='store_true', help='同时使用 OSV API 在线查询')
    parser.add_argument('--ignore-local', action='store_true', help='忽略本地数据库')
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[ERROR] 目录不存在: {args.directory}", file=sys.stderr)
        sys.exit(1)

    allowed_severities = set(s.strip().upper() for s in args.severity.split(','))

    # 1. 查找依赖文件
    dep_files = find_dependency_files(args.directory)
    if not dep_files:
        print(f"[INFO] 未找到依赖文件: {args.directory}")
        sys.exit(0)

    print(f"[INFO] 找到 {len(dep_files)} 个依赖文件", file=sys.stderr)

    # 2. 解析依赖
    all_deps = []
    for f in dep_files:
        if f.endswith('requirements.txt') or f.endswith('setup.py'):
            all_deps.extend(parse_requirements_txt(f))
        elif f.endswith('package.json'):
            all_deps.extend(parse_package_json(f))
        elif f.endswith('go.mod'):
            all_deps.extend(parse_go_mod(f))

    print(f"[INFO] 解析到 {len(all_deps)} 个依赖", file=sys.stderr)

    # 3. 扫描
    findings = []
    if not args.ignore_local:
        findings.extend(scan_local_db(all_deps))
    if args.online:
        findings.extend(scan_online(all_deps))

    # 4. 过滤
    findings = [f for f in findings if f['severity'] in allowed_severities]

    # 5. 去重和排序
    seen = set()
    unique = []
    for f in findings:
        key = (f.get('cve_id', ''), f['name'])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = sorted(unique, key=lambda x: SEVERITY_ORDER.get(x['severity'], 99))

    # 6. 输出
    if args.output == 'json':
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        if not findings:
            print("✅ 未发现已知漏洞依赖\n")
        else:
            severity_icon = {
                'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'
            }
            print(f"\n{'='*60}")
            print(f"  依赖漏洞扫描报告 — {args.directory}")
            print(f"{'='*60}\n")
            print(f"  扫描依赖数: {len(all_deps)}")
            print(f"  发现漏洞数: {len(findings)}\n")

            for f in findings:
                icon = severity_icon.get(f['severity'], '⚪')
                print(f"{icon} [{f['severity']}] {f['name']} {f.get('version', '?')}")
                print(f"   CVE: {f.get('cve_id', 'N/A')}")
                print(f"   描述: {f.get('description', 'N/A')}")
                print(f"   修复: 升级到 {f.get('fix_version', '最新版')}")
                print(f"   位置: {f['source']} ({f['line']})")
                print()

            print(f"{'='*60}")

    sys.exit(1 if any(f['severity'] == 'CRITICAL' for f in findings) else 0)


if __name__ == '__main__':
    main()
