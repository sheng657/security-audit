# Security Audit — 代码安全审计技能

对代码库、配置文件、依赖清单进行全面安全扫描，覆盖 OWASP Top 10 全部类别，输出带风险等级和可直接替换修复代码的审计报告。

## 功能特性

- 5大扫描维度：注入类、认证授权、敏感数据、供应链安全、配置安全
- 自动检测30+种硬编码密钥模式（API Key、数据库密码、私钥等）
- SQL注入检测（Python/JS/Java/PHP/Go）
- 依赖CVE扫描（requirements.txt、package.json等）
- 审计后自动更新检测规则库（无需手动维护）
- 输出带修复代码的详细审计报告

## 环境要求

### 必需

- Python 3.9+
- Linux / WSL 环境（macOS/Windows 也支持，部分路径需适配）

### Python 依赖

```bash
pip install safety pip-audit
```

- `safety` — 依赖CVE扫描（dep-scan.py使用）
- `pip-audit` — 备选的依赖扫描工具

### 可选

```bash
pip install jieba rank-bm25  # BM25检索（项目本身可能需要）
```

### 无需安装的依赖

- `secret-scan.py` — 纯正则扫描，无第三方依赖
- `sql-inject-check.py` — 纯正则扫描，无第三方依赖
- `post-audit-update.py` — 纯Python标准库，无第三方依赖

## 目录结构

```
security-audit/
├── SKILL.md                          # 技能主文档（Hermes Agent格式）
├── README.md                         # 本文件
├── scripts/
│   ├── secret-scan.py                # 硬编码密钥/密码扫描
│   ├── sql-inject-check.py           # SQL注入检测
│   ├── dep-scan.py                   # 依赖CVE扫描
│   └── post-audit-update.py          # 审计后自动更新规则库
├── reference/
│   ├── owasp-top10-cheatsheet.md     # OWASP Top 10 中文速查表
│   ├── vulnerability-patterns.md     # 按语言分类的危险代码模式
│   ├── cwe-mapping.md                # 漏洞类型 → CWE-ID 映射表
│   └── secure-coding-guide.md        # 安全编码规范摘要
└── assets/
    └── risk-level-icons.md           # 风险等级颜色/图标标识规范
```

## 快速使用

### 独立使用（不依赖Hermes Agent）

```bash
# 密钥扫描
python scripts/secret-scan.py /path/to/project

# SQL注入检测
python scripts/sql-inject-check.py /path/to/project

# 依赖CVE扫描
python scripts/dep-scan.py /path/to/project

# 审计后自动更新规则库
# 先将审计结果保存为JSON，然后：
python scripts/post-audit-update.py --findings /tmp/findings.json

# 预览模式（不实际写入）
python scripts/post-audit-update.py --findings /tmp/findings.json --dry-run
```

### 作为Hermes Agent技能使用

安装到 `~/.hermes/skills/security-audit/`，然后对 Agent 说：

- "检查一下安全"
- "有没有漏洞"
- "audit 一下"
- "安全扫描"
- "代码审计"

## 扫描覆盖范围

| 维度 | 漏洞类型 | CWE |
|------|---------|-----|
| 注入类 | SQL注入、命令注入、NoSQL注入、LDAP注入、模板注入 | CWE-89/78/943/94 |
| 认证授权 | JWT硬编码、弱密码、密码明文存储、Session固定、越权访问、IDOR | CWE-798/256/384/639 |
| 敏感数据 | 密钥硬编码、os.getenv默认值泄漏、日志打印PII、明文传输、弱加密 | CWE-798/312/327 |
| 供应链 | 依赖CVE、过期组件、恶意包、锁文件缺失 | CWE-1395 |
| 配置安全 | CORS过度开放、调试模式未关、目录遍历、文件上传无限制 | CWE-942/16/22 |

## 审计报告格式

每个发现的问题包含：

- 风险等级（CRITICAL/HIGH/MEDIUM/LOW）
- 文件位置（精确到行号）
- CWE编号 + OWASP分类
- 利用场景（攻击者如何利用）
- 问题代码 + 修复代码（可直接替换）
- 影响分析（用户数据/系统完整性/业务连续性）

## 自动更新机制

每次审计完成后，`post-audit-update.py` 自动执行：

1. 对比本次发现 vs 现有检测规则（KNOWN_PATTERNS）
2. 新模式自动追加到 `secret-scan.py`
3. 更新 `cwe-mapping.md` 和 `vulnerability-patterns.md`

这样下次审计同类项目时，新发现的漏洞模式能自动检出。

## 已知限制

- WSL下终端工具会拦截含emoji字符的命令（触发Unicode变体选择器安全检测）
- execute_code中调用search_files处理含中文路径时可能JSON解析失败，改用terminal+grep更可靠
- SQL注入检测基于正则，可能有误报/漏报，需人工复核
- 依赖CVE扫描需要网络连接

## License

MIT
