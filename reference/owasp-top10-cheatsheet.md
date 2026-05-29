# OWASP Top 10 中文速查表

> 基于 OWASP Top 10:2021 版本，补充 2025 趋势标注

---

## A01:2021 – Broken Access Control（访问控制失效）

**严重程度：** 🔴 CRITICAL

**简介：** 未正确限制已认证用户的操作，允许用户执行超出预期范围的操作。

### 识别特征

- URL 中直接暴露数据库 ID（如 `/api/users/123/orders`）未校验归属
- 管理接口无角色校验（任何用户可访问 `/admin`）
- HTTP 方法未限制（PUT/DELETE 可被未授权调用）
- JWT Token 的 `iss`/`aud` 未校验
- CORS 配置允许任意来源携带凭证

### 常见攻击

- 水平越权：用户 A 访问用户 B 的订单
- 垂直越权：普通用户执行管理员操作
- IDOR：通过遍历 ID 获取他人数据
- 目录遍历：`../../etc/passwd`

### 修复要点

- 默认拒绝（deny by default），显式授权
- 服务端校验每个请求的资源归属
- 禁用 Web 服务器目录列表
- 日志记录所有访问控制失败事件

---

## A02:2021 – Cryptographic Failures（加密失败）

**严重程度：** 🟠 HIGH

**简介：** 敏感数据未正确加密，包括传输中和存储中。

### 识别特征

- 密码用 MD5/SHA1 存储（无盐或盐太短）
- 数据库中敏感字段明文存储（身份证号、手机号、银行卡）
- 使用 DES/3DES/RC4 等弱算法
- HTTP 传输敏感数据（未用 HTTPS）
- TLS 证书配置不当（支持 TLS 1.0/1.1）
- 自行实现加密算法（非标准库）

### 常见攻击

- 中间人攻击窃取明文传输数据
- 数据库泄露后敏感数据直接可读
- 彩虹表攻击破解 MD5 密码

### 修复要点

- 密码使用 bcrypt/scrypt/Argon2（带适当 work factor）
- 敏感数据 AES-256-GCM 加密存储
- 强制 HTTPS + HSTS
- 密钥使用 KMS 或 vault 管理，不写入代码

---

## A03:2021 – Injection（注入）

**严重程度：** 🔴 CRITICAL

**简介：** 用户输入未经过滤/转义直接拼接到查询或命令中。

### 识别特征

**SQL 注入：**
- 字符串拼接 SQL（`"SELECT ... " + input`）
- f-string / format 拼接 SQL
- ORM 的 `raw()` / `extra()` 方法

**命令注入：**
- `os.system(input)`
- `subprocess.call(shell=True)`
- `eval(user_input)`
- `exec(user_code)`

**XSS（跨站脚本）：**
- `innerHTML` 直接插入用户输入
- `document.write(userInput)`
- 模板引擎中 `|safe` / `{{{content}}}`

**NoSQL 注入：**
- MongoDB 中 `$where: "this.name == '" + input + "'"`
- 未过滤的 `$gt`、`$ne` 操作符

### 修复要点

- SQL：使用参数化查询（prepared statement）
- 命令：避免 shell=True，使用列表参数
- XSS：输出编码（HTML entity / CSP）
- NoSQL：使用白名单校验操作符

---

## A04:2021 – Insecure Design（不安全设计）

**严重程度：** 🟠 HIGH

**简介：** 架构层面缺少安全控制，非代码 bug 而是设计缺陷。

### 识别特征

- 缺少威胁建模（STRIDE）
- 关键操作无审计日志
- 密码找回流程可枚举用户
- 批量操作无速率限制
- 缺少安全设计评审

### 修复要点

- 在设计阶段进行威胁建模
- 建立安全设计模式库
- 分层安全控制（纵深防御）
- 编写滥用用例（Abuse Case）

---

## A05:2021 – Security Misconfiguration（安全配置错误）

**严重程度：** 🟡 MEDIUM

**简介：** 默认配置、不完整配置、开放式云存储等。

### 识别特征

- `DEBUG = True`（Django/Flask 生产环境）
- `NODE_ENV = development`（生产环境）
- 默认账号密码未修改（admin/admin）
- 不必要的端口/服务开放
- 错误信息泄露堆栈跟踪
- XML 外部实体（XXE）未禁用

### 修复要点

- 最小化安装（删除默认账号、示例文件）
- 自动化配置审查
- 分段架构（组件间最小权限）
- 安全基线配置模板

---

## A06:2021 – Vulnerable and Outdated Components（组件漏洞）

**严重程度：** 🟡 MEDIUM

**简介：** 使用了已知存在漏洞的组件/库。

### 识别特征

- `requirements.txt` / `package.json` 无版本锁定
- 依赖超过 24 个月未更新
- 无法获取组件的 CVE 信息
- 未使用 Dependabot / Snyk / Renovate
- 使用已废弃的库

### 修复要点

- 仅从官方源安装依赖
- 使用 lock 文件锁定版本
- 配置自动漏洞扫描（Dependabot/Renovate）
- 定期审计依赖树

---

## A07:2021 – Identification and Authentication Failures（认证失败）

**严重程度：** 🟠 HIGH

**简介：** 身份认证机制存在缺陷。

### 识别特征

- 允许弱密码（无最小长度/复杂度要求）
- 未实现多因素认证（MFA）
- Session ID 在 URL 中传输
- 登录后未重新生成 Session ID
- 密码找回功能可枚举用户（错误消息不同）
- 暴力破解无防护（无锁定/速率限制）

### 修复要点

- 强制密码策略（最少 8 位，含大小写+数字）
- 实施 MFA
- 登录后重新生成 Session ID
- 部署 rate limiting + 账户锁定

---

## A08:2021 – Software and Data Integrity Failures（数据完整性失败）

**严重程度：** 🟠 HIGH

**简介：** 未验证软件/数据的完整性，包括不安全的反序列化。

### 识别特征

- Python: `pickle.loads(untrusted_data)`
- Java: `ObjectInputStream.readObject()`
- PHP: `unserialize(untrusted_data)`
- CI/CD 管道未签名验证
- 引用第三方组件未校验 hash
- 自动更新机制不验证签名

### 修复要点

- 避免反序列化不可信数据
- 使用数字签名验证软件来源
- CI/CD 产物签名 + 校验
- 使用 SRI（Subresource Integrity）验证 CDN 资源

---

## A09:2021 – Security Logging and Monitoring Failures（日志监控不足）

**严重程度：** 🟡 MEDIUM

**简介：** 缺少足够的日志记录和监控，无法及时发现攻击。

### 识别特征

- 登录失败未记录
- 高权限操作未审计
- 日志仅存本地（服务器被入侵即丢失）
- 未配置实时告警
- 日志中包含敏感信息（密码、Token）

### 修复要点

- 记录所有认证事件和权限变更
- 日志集中存储（ELK/Splunk）
- 配置实时告警规则
- 敏感字段脱敏后再记录

---

## A10:2021 – Server-Side Request Forgery (SSRF)（服务端请求伪造）

**严重程度：** 🟡 MEDIUM

**简介：** 应用程序在获取远程资源时未校验用户提供的 URL。

### 识别特征

- 用户可控的 URL 直接传给 HTTP 客户端
- 未限制内网 IP 访问
- 未校验 URL scheme（允许 `file://`、`gopher://`）
- DNS 重绑定防护缺失

### 修复要点

- URL 白名单校验
- 禁止访问内网 IP 段
- 禁用非 HTTP scheme
- 使用 network 分段隔离

---

## 2025 趋势补充

| 新兴风险 | 说明 |
|---------|------|
| LLM 注入 | Prompt Injection，通过操纵 AI 输入绕过安全控制 |
| API 安全 | GraphQL 批量查询滥用、API 速率限制不足 |
| 供应链攻击 | npm/PyPI 恶意包、构建管道投毒 |
| 容器安全 | Docker 镜像漏洞、Kubernetes RBAC 配置错误 |
| 密钥管理 | 云服务环境变量泄露、Secret 注入到镜像 |
