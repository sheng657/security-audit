# 🔒 Security Audit — 代码安全审计技能

> 对代码库、配置文件、依赖清单进行全面安全扫描，覆盖 OWASP Top 10 全部类别，输出带风险等级和可直接替换修复代码的审计报告。

![Python 3.9+](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)
![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-0052CC?logo=owasp&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

---

## ✨ 功能特性

| 能力 | 说明 |
|------|------|
| 🔑 **密钥扫描** | 自动检测 30+ 种硬编码密钥模式（API Key、数据库密码、私钥等），支持 `sk-`/`ak-`/`ghp_` 等前缀 |
| 💉 **SQL 注入检测** | 覆盖 Python / JS / Java / PHP / Go 五种语言的 SQL 拼接模式 |
| 📦 **依赖 CVE 扫描** | 解析 requirements.txt / package.json / pom.xml 等，自动查询已知漏洞 |
| 🔄 **规则自进化** | 每次审计后自动更新检测规则库，越用越强 |
| 📊 **专业报告** | 按风险等级分类，每个漏洞含 CWE 编号、利用场景、修复代码 |
| 🌐 **多语言支持** | 报告支持中文/英文双语输出 |

---

## 📋 环境要求

### 必需

| 项目 | 版本 | 说明 |
|------|------|------|
| Python | 3.9+ | 所有脚本基于 Python 标准库 + 少量依赖 |
| 操作系统 | Linux / WSL / macOS / Windows | 部分路径需适配 |

### Python 依赖

```bash
pip install safety pip-audit
```

| 包名 | 用途 | 必需？ |
|------|------|--------|
| `safety` | 依赖 CVE 漏洞数据库查询 | dep-scan.py 需要 |
| `pip-audit` | 备选依赖扫描工具 | 可选 |

### 零依赖脚本（开箱即用）

| 脚本 | 说明 |
|------|------|
| `secret-scan.py` | 纯正则扫描，无第三方依赖 |
| `sql-inject-check.py` | 纯正则扫描，无第三方依赖 |
| `post-audit-update.py` | 纯 Python 标准库，无第三方依赖 |

---

## 📁 目录结构

```
security-audit/
│
├── SKILL.md                          # 🤖 技能主文档（Hermes Agent 格式）
├── README.md                         # 📖 本文件
├── .gitignore                        # 忽略规则
│
├── scripts/                          # 🔧 核心扫描脚本
│   ├── secret-scan.py                #    硬编码密钥/密码扫描（30+ 模式）
│   ├── sql-inject-check.py           #    SQL 注入检测（5 种语言）
│   ├── dep-scan.py                   #    依赖 CVE 扫描
│   └── post-audit-update.py          #    审计后自动更新规则库
│
├── reference/                        # 📚 安全知识库
│   ├── owasp-top10-cheatsheet.md     #    OWASP Top 10 中文速查表
│   ├── vulnerability-patterns.md     #    按语言分类的危险代码模式库
│   ├── cwe-mapping.md                #    漏洞类型 → CWE-ID 映射表
│   └── secure-coding-guide.md        #    安全编码规范摘要
│
└── assets/                           # 🎨 资源文件
    └── risk-level-icons.md           #    风险等级颜色/图标标识规范
```

---

## 🚀 快速开始

### 方式一：独立使用（不依赖 Hermes Agent）

```bash
# 1️⃣ 克隆仓库
git clone git@github.com:sheng657/security-audit.git
cd security-audit

# 2️⃣ 安装可选依赖（如需依赖扫描）
pip install safety pip-audit

# 3️⃣ 运行扫描
python scripts/secret-scan.py /path/to/project          # 密钥扫描
python scripts/sql-inject-check.py /path/to/project     # SQL注入检测
python scripts/dep-scan.py /path/to/project             # 依赖CVE扫描

# 4️⃣ 审计后自动更新规则库
# 先将审计结果保存为 JSON，然后：
python scripts/post-audit-update.py --findings /tmp/findings.json

# 预览模式（不实际写入，仅展示变更）
python scripts/post-audit-update.py --findings /tmp/findings.json --dry-run
```

### 方式二：作为 Hermes Agent 技能使用

```bash
# 安装到 Hermes（三选一）

# 方式 A：git clone
git clone git@github.com:sheng657/security-audit.git ~/.hermes/skills/security-audit

# 方式 B：Hermes 命令安装
hermes skills install sheng657/security-audit

# 方式 C：手动复制
cp -r security-audit/ ~/.hermes/skills/security-audit/
```

安装后，对 Agent 说以下任意触发语即可：

| 触发语 | 示例 |
|--------|------|
| 检查安全 | "检查一下项目安全"、"帮我看看有没有安全问题" |
| 漏洞扫描 | "有没有漏洞"、"扫描一下漏洞" |
| 代码审计 | "audit 一下"、"做一次代码审计" |
| 安全扫描 | "安全扫描"、"跑个安全检查" |

---

## 🎯 扫描覆盖范围

### 按 OWASP Top 10 分类

| OWASP 分类 | 扫描维度 | 检测内容 | CWE |
|------------|---------|---------|-----|
| **A03 注入** | 注入类 | SQL 注入、命令注入、NoSQL 注入、LDAP 注入、模板注入 | CWE-89 / 78 / 943 / 94 |
| **A07 身份认证** | 认证授权 | JWT 硬编码、弱密码、密码明文存储、Session 固定、越权访问、IDOR | CWE-798 / 256 / 384 / 639 |
| **A02 加密失败** | 敏感数据 | 密钥硬编码、`os.getenv()` 默认值泄漏、日志打印 PII、明文传输、弱加密算法 | CWE-798 / 312 / 327 |
| **A06 组件漏洞** | 供应链安全 | 依赖 CVE、过期组件、恶意包、锁文件缺失 | CWE-1395 |
| **A05 配置错误** | 配置安全 | CORS 过度开放、调试模式未关、目录遍历、文件上传无限制 | CWE-942 / 16 / 22 |

### 支持的编程语言

| 脚本 | 支持语言 |
|------|---------|
| `secret-scan.py` | Python、JavaScript、Java、Go、PHP、Ruby、Docker、YAML、.env |
| `sql-inject-check.py` | Python、JavaScript、Java、PHP、Go |
| `dep-scan.py` | pip (requirements.txt)、npm (package.json)、Maven (pom.xml)、pipenv、poetry |

---

## 📊 审计报告格式

每个发现的问题包含以下完整信息：

```
┌──────────────────────────────────────────────────────┐
│ 🔴 CRITICAL — 硬编码 API 密钥                         │
├──────────────────────────────────────────────────────┤
│ 文件: api_service/config.py:7                         │
│ CWE:  CWE-798 (Use of Hard-coded Credentials)        │
│ OWASP: A02:2021 - Cryptographic Failures             │
├──────────────────────────────────────────────────────┤
│ 🔍 利用场景:                                          │
│    攻击者可通过 Git 历史/源码泄露获取 API Key，          │
│    冒充合法用户调用付费 API，造成经济损失                   │
├──────────────────────────────────────────────────────┤
│ 💻 问题代码:                                          │
│    api_key = "sk-1234567890abcdef"                    │
├──────────────────────────────────────────────────────┤
│ ✅ 修复代码:                                          │
│    api_key = os.environ.get("DEEPSEEK_API_KEY")       │
│    if not api_key:                                    │
│        raise ValueError("缺少 DEEPSEEK_API_KEY")      │
├──────────────────────────────────────────────────────┤
│ 📋 影响分析:                                          │
│    • 用户数据: API 滥用可能导致用户查询记录泄露            │
│    • 系统完整性: 密钥泄露影响第三方服务账户安全             │
│    • 业务连续性: API 额度耗尽导致服务中断                 │
└──────────────────────────────────────────────────────┘
```

### 风险等级定义

| 等级 | 颜色 | 定义 | 修复时限 |
|------|------|------|---------|
| 🔴 **CRITICAL** | 红色 | 可被直接利用，造成重大安全事件 | **立即修复** |
| 🟠 **HIGH** | 橙色 | 在特定条件下可被利用，影响较大 | **24 小时内** |
| 🟡 **MEDIUM** | 黄色 | 需要多个条件组合才能利用 | **1 周内** |
| 🟢 **LOW** | 绿色 | 安全最佳实践偏差，风险较低 | **计划修复** |

---

## 🔄 自进化机制

每次审计完成后，`post-audit-update.py` 自动执行以下流程：

```
审计结果 (findings)
        │
        ▼
┌───────────────────┐
│ 1. 对比现有规则    │  KNOWN_PATTERNS 列表去重
│    (发现 vs 规则)  │
└───────┬───────────┘
        │ 新发现
        ▼
┌───────────────────┐
│ 2. 分类路由        │  classify_finding() 按类型分发
└───┬───┬───┬───┬───┘
    │   │   │   │
    ▼   ▼   ▼   ▼
  密钥 SQL  依赖  CWE
  扫描 注入  扫描  映射
    │   │   │   │
    ▼   ▼   ▼   ▼
┌───────────────────┐
│ 3. 自动追加规则    │  正则模式自动生成
│    更新参考文档    │  知识库同步升级
└───────────────────┘
```

> 💡 **效果**：每次审计都是学习过程，同类项目越审越快、越审越准。

---

## 📝 输出示例

### 密钥扫描输出

```
╔══════════════════════════════════════════════════════╗
║  🔑 秘钥扫描结果                                     ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  🔴 CRITICAL (2)                                     ║
║  ├─ api_service/config.py:7                          ║
║  │   DeepSeek API Key (sk-*)                         ║
║  │   CWE-798 | OWASP A02:2021                       ║
║  │                                                   ║
║  └─ ragas_evaluation.py:41                           ║
║      DeepSeek API Key (sk-*)                         ║
║      CWE-798 | OWASP A02:2021                       ║
║                                                      ║
║  🟡 MEDIUM (1)                                       ║
║  └─ .env.example                                     ║
║      DATABASE_PASSWORD = "123456"                    ║
║      CWE-256 | OWASP A07:2021                       ║
║                                                      ║
╠══════════════════════════════════════════════════════╣
║  📊 统计: CRITICAL=2  HIGH=0  MEDIUM=1  LOW=0        ║
╚══════════════════════════════════════════════════════╝
```

---

## ⚠️ 已知限制

| 限制 | 说明 | 解决方案 |
|------|------|---------|
| WSL 终端 Unicode 拦截 | 含 emoji 字符的命令可能触发安全检测 | 使用 terminal 工具执行，避开 emoji |
| 中文路径 JSON 解析 | `execute_code` 中 `search_files` 处理含中文路径时可能失败 | 改用 `terminal` + `grep` |
| SQL 注入误报 | 基于正则匹配，可能产生误报/漏报 | 需人工复核关键发现 |
| 依赖扫描需网络 | `safety` / `pip-audit` 需联网查询漏洞库 | 确保网络连接或使用代理 |
| 不支持二进制文件 | 扫描仅覆盖文本源码 | 不含 `.dll` / `.so` / `.exe` 等 |

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 发起 Pull Request

---

## 📄 License

MIT License — 详见 [LICENSE](LICENSE) 文件

