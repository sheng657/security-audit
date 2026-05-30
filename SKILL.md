---
name: security-audit
version: 1.1.0
category: security
description: 对代码和配置进行安全扫描，识别常见漏洞并提供可落地的修复方案
tags: [security, audit, vulnerability, OWASP, CWE, penetration-testing]
triggers:
  - "检查一下安全"
  - "有没有漏洞"
  - "audit 一下"
  - "安全扫描"
  - "代码审计"
  - "security check"
---

# Security Audit — 代码安全审计技能

对代码库、配置文件、依赖清单进行全面安全扫描，覆盖 OWASP Top 10 全部类别，输出带风险等级和可直接替换修复代码的审计报告。

## 适用场景

- 用户说"检查一下安全"、"有没有漏洞"、"audit 一下"
- 用户处理用户输入、数据库查询、文件上传、身份鉴权
- 用户配置了 API 密钥、数据库连接串
- 用户准备上线或发布新版本

## 扫描维度（必须全部覆盖）

### 1. 注入类

| 漏洞类型 | 检测要点 | 典型语言 |
|---------|---------|---------|
| SQL 注入 | 字符串拼接 SQL、未使用参数化查询、ORM raw query | Python/JS/Java/Go |
| NoSQL 注入 | MongoDB `$where` 直接拼接用户输入、未校验查询操作符 | Node.js/Python |
| 命令注入 | `os.system()`、`subprocess.call(shell=True)`、`exec()`、`eval()` | Python/JS/PHP |
| LDAP 注入 | 用户输入直接拼接 LDAP 过滤器 | Java/C# |
| 模板注入 | Jinja2/Twig/Handlebars 中未转义用户输入 | Python/JS/PHP |

### 2. 认证授权

| 漏洞类型 | 检测要点 |
|---------|---------|
| JWT 硬编码密钥 | `.env` 或源码中出现 `JWT_SECRET`、`jwt.sign(key=...)` |
| 弱密码策略 | 无最小长度、无复杂度要求、默认密码未改 |
| 密码明文存储 | 数据库中存储未哈希的密码、代码注释明确移除加密 |
| Session 固定 | 登录后未重新生成 Session ID |
| 越权访问 | 未校验资源所属用户（水平越权）、角色权限（垂直越权） |
| IDOR | URL/请求中直接使用数据库 ID 未做归属校验 |

### 3. 敏感数据

| 漏洞类型 | 检测要点 |
|---------|---------|
| 密钥硬编码 | 源码中出现 API Key、Token、密码明文 |
| os.environ 默认值泄漏 | `os.getenv("KEY", "real-key-here")` 默认值含真实密钥 |
| 日志打印 PII | `print(email)`、`console.log(phone)`、日志含身份证号 |
| 明文传输 | HTTP 未使用 HTTPS、敏感接口未 TLS |
| 不安全反序列化 | Python `pickle.loads()`、Java `ObjectInputStream`、PHP `unserialize()` |
| 弱加密 | MD5/SHA1 用于密码、DES、ECB 模式 |

### 4. 供应链安全

| 漏洞类型 | 检测要点 |
|---------|---------|
| 依赖 CVE | requirements.txt / package.json / go.mod 中已知漏洞版本 |
| 过期组件 | 超过 12 个月未更新的依赖 |
| 恶意包 | 包名 typosquatting（如 `requets` vs `requests`） |
| 锁文件缺失 | 无 `poetry.lock` / `package-lock.json` / `go.sum` |

### 5. 配置安全

| 漏洞类型 | 检测要点 |
|---------|---------|
| CORS 过度开放 | `Access-Control-Allow-Origin: *` + 携带凭证 |
| 调试模式未关 | `DEBUG=True` 在生产配置、`NODE_ENV=development` |
| 目录遍历 | 文件操作中拼接 `../` 未过滤 |
| 文件上传限制 | 未限制文件类型/大小、未重命名上传文件 |
| 敏感端点暴露 | `/debug`、`/admin`、`/actuator`、`/phpinfo` |
| 无 .gitignore | 密钥/缓存文件可能随代码提交到仓库 |
| 无 requirements.txt | 依赖未版本锁定，部署可能不兼容 |

### 6. 数据安全

| 漏洞类型 | 检测要点 |
|---------|---------|
| 密码明文存储 | 数据库中存储未哈希的密码 |
| 弱哈希算法 | 使用 MD5/SHA1 做密码哈希 |
| 明文配置 | 数据库连接串含明文密码 |

## 输出格式

每个发现的问题必须包含以下字段：

```
[风险等级图标] CRITICAL / HIGH / MEDIUM / LOW

文件: src/api/user.py:42
漏洞类型: SQL 注入（字符串拼接）
CWE 编号: CWE-89
OWASP 分类: A03:2021 - Injection

利用场景:
  攻击者提交 user_id = "1 OR 1=1 --" 可绕过查询条件,
  获取全表用户数据。若结合 UNION SELECT 还可读取其他表。

影响范围:
  - 用户数据: [可访问的数据类型和范围]
  - 系统完整性: [对系统完整性的威胁程度]
  - 业务连续性: [对业务运营的影响程度]

问题代码:
  ```python
  cursor.execute("SELECT * FROM users WHERE id = " + user_id)
  ```

修复代码:
  ```python
  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
  ```

参考链接:
  - https://cwe.mitre.org/data/definitions/89.html
  - https://owasp.org/Top10/A03_2021-Injection/
```

## 完整报告模板

```
# 安全审计报告

项目: [项目名]
扫描时间: [时间]
扫描范围: [文件数 / 目录]
技术栈: [语言/框架]

## 风险概览

[CRITICAL图标] CRITICAL: X 个
[HIGH图标] HIGH:     X 个
[MEDIUM图标] MEDIUM:   X 个
[LOW图标] LOW:      X 个

## 详细发现

[按风险等级从高到低列出所有问题，每个问题包含:]
- 文件位置（文件名:行号）
- 漏洞类型和 CWE 编号
- 利用场景（攻击者如何利用）
- 影响范围（用户数据、系统完整性、业务连续性）
- 问题代码片段
- 修复代码（可直接替换）
- 参考链接

## 安全的部分（做得好的）

[列出代码中安全的做法，给用户正向反馈]

## 修复优先级建议

1. 立即修复: [CRITICAL + HIGH 列表]
2. 计划修复: [MEDIUM 列表]
3. 择机优化: [LOW 列表]

## 安全加固建议

[针对项目特点的综合安全改进建议]
```

## 执行流程

### 第一步：确定扫描范围

1. 询问用户要扫描的目录，或自动检测当前项目根目录
2. 识别项目语言和技术栈（查看 package.json / requirements.txt / go.mod / pom.xml / Cargo.toml）
3. 加载 `reference/vulnerability-patterns.md` 获取对应语言的检测规则

### 第二步：运行自动化扫描

按以下顺序执行：

```
1. scripts/secret-scan.py     -> 先扫硬编码密钥（最快、最常见）
2. scripts/sql-inject-check.py -> 扫描注入类漏洞
3. scripts/dep-scan.py        -> 扫描依赖 CVE
4. 正则扫描其余维度（配置、认证、敏感数据）
```

**pitfall**: terminal 工具会拦截含 emoji 字符的命令（触发 Unicode 变体选择器安全检测），扫描命令中不要用 emoji。

**pitfall**: execute_code 中调用 search_files 处理含中文路径的 WSL 项目时，可能因 JSON 解析失败报错。改用 terminal + grep 更可靠。

**pitfall**: 三个扫描脚本的 CLI 接口不一致！`secret-scan.py` 支持 `--exclude` 参数排除目录，但 `sql-inject-check.py` 和 `dep-scan.py` **不支持** `--exclude`。对 sql-inject-check.py 和 dep-scan.py 只需传目录参数即可（它们内置了排除规则）。如果传了不支持的参数会直接报错退出。

**pitfall**: 扫描工具的误报率极高，必须人工复核。典型误报模式：
- **硬编码密钥误报**: 示例值（`your-key-here`）、占位符（`no-key-required`、`aws-sdk`）、国际化翻译文件中的 `secret`/`密码` 翻译、文档中的 `ghp_...` 示例
- **SQL注入误报**: 使用硬编码表名/触发器名的 f-string（非用户输入）、`_wrap_panel_text()` 等文本格式化函数被误判为 SQLAlchemy text() 拼接
- **Twilio SID 误报**: 以 `AC` 开头的区块链合约地址（如 USDT 的 `0xdAC17F958D2ee523...`）会被正则误匹配
- **shell=True 误报**: skills_guard.py 中的检测规则引用、注释中的说明文字

正确做法：先跑工具拿原始数据，然后用 `is_likely_false_positive()` 逻辑或人工判断过滤。报告中应分两列呈现——"工具报告数"和"实际确认数"。

### 第三步：人工复核 + 补充

自动化工具无法覆盖的项目：
- 业务逻辑漏洞（越权、IDOR）-> 需理解业务代码
- 并发安全（竞态条件、TOCTOU）
- 密码学误用（自定义加密算法）
- 密码明文存储（需人工审查 database 模块）
- 配置问题（CORS、.gitignore、requirements.txt 缺失）

对不确定的发现，标记为 **"待验证"**，不制造恐慌。

### 第四步：生成审计报告

按上面的「完整报告模板」输出，每个发现必须包含：
- 风险等级 + CWE 编号
- 文件位置（精确到行号）
- 利用场景
- 影响范围
- 问题代码 + 修复代码
- 参考链接

### 第五步：审计后自动更新规则库

每次审计完成后，运行 `scripts/post-audit-update.py` 自动将新发现的漏洞模式追加到检测规则库：

```bash
# 先把审计结果存为 JSON
# 然后运行自动更新
python scripts/post-audit-update.py --findings findings.json

# 预览模式（不实际写入）
python scripts/post-audit-update.py --findings findings.json --dry-run
```

该脚本会：
1. 对比发现的问题与现有 KNOWN_PATTERNS
2. 未覆盖的模式自动追加到 secret-scan.py 的 SECRET_PATTERNS
3. 更新 cwe-mapping.md 和 vulnerability-patterns.md

## 示例

### 示例 1：Python SQL 注入

**发现：** `src/models/user.py:38` 存在字符串拼接 SQL

```python
# 问题代码
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)

# 修复代码（参数化查询）
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

CWE-89 | CRITICAL | 攻击者可注入 `admin' --` 绕过认证
影响范围: 所有用户数据可被泄露，系统完整性受到严重威胁

---

### 示例 2：React XSS

**发现：** `src/components/Comment.jsx:15` 使用 `dangerouslySetInnerHTML`

```jsx
// 问题代码
<div dangerouslySetInnerHTML={{ __html: comment.content }} />

// 修复代码（使用 DOMPurify）
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.content) }} />
```

CWE-79 | HIGH | 攻击者可注入 `<script>` 窃取用户 Cookie
影响范围: 用户会话可被劫持，业务连续性受到威胁

---

### 示例 3：.env 泄露

**发现：** `.env` 文件已被提交到 Git 仓库

```bash
# 修复步骤
# 1. 从仓库移除
git rm --cached .env
echo ".env" >> .gitignore

# 2. 轮换所有已泄露的密钥（必须！）
# 3. 用 BFG Repo-Cleaner 清除 Git 历史
bfg --delete-files .env
git reflog expire --expire=now --all
git gc --prune=now
```

CWE-312 | CRITICAL | 攻击者可通过 Git 历史恢复所有密钥

---

### 示例 4：os.environ 默认值泄漏真实密钥

**发现：** `config.py:7` 硬编码了 DeepSeek API Key 作为默认值

```python
# 问题代码
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "sk-768...5d6b")

# 修复代码
DEEPSEEK_API_KEY = os.environ["DEEPSEEK_API_KEY"]  # 不给默认值
```

CWE-798 | CRITICAL | 源码泄漏 = API Key 全部暴露
影响范围: 任何拿到源码的人可直接调用 API，造成经济损失

---

### 示例 5：密码明文存储

**发现：** `database.py:60` 注释明确写着"移除密码加密，直接比对明文密码"

```python
# 问题代码
# 移除密码加密，直接比对明文密码
cursor.execute(
    "SELECT user_id FROM users WHERE username = %s AND password = %s",
    (username, password)
)

# 修复代码（使用 PBKDF2 哈希）
import hashlib, os

def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + dk

def verify_password(password, stored):
    salt = stored[:16]
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return stored == salt + dk
```

CWE-256 | HIGH | 数据库被拖库后所有用户密码直接暴露

## 注意事项

1. **必须给修复代码**：禁止只给理论建议，每个发现必须附带可直接替换的修复代码
2. **精确行号**：文件位置精确到行号，方便用户定位
3. **影响范围分析**：每个发现都要分析对用户数据、系统完整性、业务连续性的影响程度
4. **标记不确定性**：不确定的漏洞标记为"待验证"，不制造恐慌
5. **优先级明确**：按 CRITICAL > HIGH > MEDIUM > LOW 排列，给出修复优先级
6. **合并同类项**：同类型漏洞集中在同一模式时，合并报告注明影响范围
7. **正向反馈**：列出代码中安全的做法，让用户知道哪些做得好
8. **安全加固建议**：报告末尾给出项目整体的安全改进建议（代码、配置、流程三个层面）

## 快速扫描模式（推荐用于新项目初次扫描）

当需要快速评估一个新项目时，直接用 terminal grep 比运行完整脚本更快更可靠：

```bash
# 1. 找出所有源文件
find <项目目录> -name "*.py" -o -name "*.html" -o -name "*.js" | grep -v __pycache__

# 2. 密钥/凭据扫描
grep -rn --include="*.py" -E "(api[_-]?key|secret|token|password)\s*[=:]\s*['\"][^'\"]{10,}" .
grep -rn --include="*.py" "sk-" .        # sk- 开头的 API Key
grep -rn --include="*.py" -E "os\.environ\.get\([^,]+,\s*['\"][^'\"]{10,}['\"]" .  # env 默认值泄漏
grep -rn --include="*.py" -E "os\.getenv\([^,]+,\s*['\"][^'\"]{10,}['\"]" .  # os.getenv 默认值

# 3. SQL 注入
grep -rn --include="*.py" -E "(execute|query)\s*\(.*(\+|f\"|format|%s)" .

# 4. 路径遍历
grep -rn --include="*.py" -E "os\.path\.join\(.*file\.filename" .

# 5. XSS
grep -rn --include="*.html" "innerHTML" .

# 6. 命令注入
grep -rn --include="*.py" -E "os\.system\(|subprocess.*shell=True" .

# 7. 不安全配置
grep -rn --include="*.py" -iE "debug\s*=\s*True|cors|allow_origin" .

# 8. 明文密码
grep -rn --include="*.py" -iE "密码.*明文|明文.*密码|移除.*加密" .

# 9. 缺少安全文件
ls .gitignore requirements.txt .env .env.example 2>&1
```

## 辅助脚本

| 脚本 | 用途 | 用法 |
|-----|------|------|
| `scripts/dep-scan.py` | 扫描依赖文件的已知 CVE | `python dep-scan.py <目录>` |
| `scripts/secret-scan.py` | 检测硬编码密钥和密码 | `python secret-scan.py <目录>` |
| `scripts/sql-inject-check.py` | 识别 SQL 拼接代码 | `python sql-inject-check.py <目录>` |
| `scripts/post-audit-update.py` | 审计后自动更新检测规则库 | `python post-audit-update.py --findings findings.json` |

## 参考文档

| 文档 | 内容 |
|-----|------|
| `reference/owasp-top10-cheatsheet.md` | OWASP Top 10 中文速查表 |
| `reference/vulnerability-patterns.md` | 按语言分类的危险代码模式 |
| `reference/cwe-mapping.md` | 漏洞类型 -> CWE-ID 映射表 |
| `reference/secure-coding-guide.md` | 安全编码规范摘要 |
| `assets/risk-level-icons.md` | 风险等级颜色/图标标识规范 |