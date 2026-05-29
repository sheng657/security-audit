# 漏洞类型与 CWE 编号映射表

> CWE (Common Weakness Enumeration) 由 MITRE 维护，是漏洞分类的国际标准

---

## 注入类

| 漏洞类型 | CWE-ID | CWE 名称 | 严重程度 | OWASP 分类 |
|---------|--------|---------|---------|-----------|
| SQL 注入 | CWE-89 | SQL Injection | 🔴 CRITICAL | A03:2021 |
| NoSQL 注入 | CWE-943 | Improper Neutralization of Special-Elements in a NoSQL Query | 🟠 HIGH | A03:2021 |
| 命令注入 | CWE-78 | OS Command Injection | 🔴 CRITICAL | A03:2021 |
| LDAP 注入 | CWE-90 | LDAP Injection | 🟠 HIGH | A03:2021 |
| XSS（存储型） | CWE-79 | Cross-site Scripting (Stored) | 🟠 HIGH | A03:2021 |
| XSS（反射型） | CWE-79 | Cross-site Scripting (Reflected) | 🟠 HIGH | A03:2021 |
| XSS（DOM 型） | CWE-79 | Cross-site Scripting (DOM-based) | 🟠 HIGH | A03:2021 |
| 模板注入（SSTI） | CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine | 🔴 CRITICAL | A03:2021 |
| CRLF 注入 | CWE-113 | HTTP Response Splitting | 🟡 MEDIUM | A03:2021 |
| HTTP 头注入 | CWE-644 | Improper Neutralization of HTTP Headers | 🟠 HIGH | A03:2021 |
| XPath 注入 | CWE-91 | XML Injection | 🟠 HIGH | A03:2021 |
| XML 外部实体（XXE） | CWE-611 | Improper Restriction of XML External Entity Reference | 🟠 HIGH | A05:2021 |
| 代码注入 | CWE-94 | Code Injection | 🔴 CRITICAL | A03:2021 |
| 表达式语言注入 | CWE-917 | Improper Neutralization of Script-Ending Delimiters | 🔴 CRITICAL | A03:2021 |

## 认证授权

| 漏洞类型 | CWE-ID | CWE 名称 | 严重程度 | OWASP 分类 |
|---------|--------|---------|---------|-----------|
| 硬编码凭证 | CWE-798 | Use of Hard-coded Credentials | 🔴 CRITICAL | A07:2021 |
| 弱密码策略 | CWE-521 | Weak Password Requirements | 🟡 MEDIUM | A07:2021 |
| 默认凭证 | CWE-798 | Use of Hard-coded Credentials | 🔴 CRITICAL | A07:2021 |
| Session 固定 | CWE-384 | Session Fixation | 🟠 HIGH | A07:2021 |
| 缺少认证 | CWE-306 | Missing Authentication for Critical Function | 🔴 CRITICAL | A07:2021 |
| 密码明文存储 | CWE-256 | Unprotected Storage of Credentials | 🔴 CRITICAL | A02:2021 |
| JWT 算法混淆 | CWE-347 | Improper Verification of Cryptographic Signature | 🟠 HIGH | A02:2021 |
| 越权访问（水平） | CWE-639 | Authorization Bypass Through User-Controlled Key | 🟠 HIGH | A01:2021 |
| 越权访问（垂直） | CWE-269 | Improper Privilege Management | 🟠 HIGH | A01:2021 |
| IDOR | CWE-639 | Authorization Bypass Through User-Controlled Key | 🟠 HIGH | A01:2021 |
| 暴力破解无防护 | CWE-307 | Improper Restriction of Excessive Authentication Attempts | 🟡 MEDIUM | A07:2021 |
| 空密码 | CWE-521 | Weak Password Requirements | 🟠 HIGH | A07:2021 |

## 敏感数据

| 漏洞类型 | CWE-ID | CWE 名称 | 严重程度 | OWASP 分类 |
|---------|--------|---------|---------|-----------|
| 明文传输 | CWE-319 | Cleartext Transmission of Sensitive Information | 🟠 HIGH | A02:2021 |
| 明文存储 | CWE-312 | Cleartext Storage of Sensitive Information | 🔴 CRITICAL | A02:2021 |
| 日志泄露敏感数据 | CWE-532 | Insertion of Sensitive Information into Log File | 🟡 MEDIUM | A09:2021 |
| 错误信息泄露 | CWE-209 | Generation of Error Message Containing Sensitive Information | 🟡 MEDIUM | A04:2021 |
| 客户端数据缓存 | CWE-922 | Insecure Storage of Sensitive Information | 🟡 MEDIUM | A02:2021 |
| Cookie 无 HttpOnly | CWE-1004 | Sensitive Cookie Without 'HttpOnly' Flag | 🟡 MEDIUM | A05:2021 |
| Cookie 无 Secure | CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Flag | 🟡 MEDIUM | A05:2021 |
| 弱哈希（密码） | CWE-328 | Reversible One-Way Hash | 🟠 HIGH | A02:2021 |
| 不安全反序列化 | CWE-502 | Deserialization of Untrusted Data | 🔴 CRITICAL | A08:2021 |
| 弱加密算法 | CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | 🟠 HIGH | A02:2021 |
| 弱随机数 | CWE-330 | Use of Insufficiently Random Values | 🟠 HIGH | A02:2021 |
| 密钥泄露在代码仓库 | CWE-798 | Use of Hard-coded Credentials | 🔴 CRITICAL | A02:2021 |

## 配置安全

| 漏洞类型 | CWE-ID | CWE 名称 | 严重程度 | OWASP 分类 |
|---------|--------|---------|---------|-----------|
| 调试模式开启 | CWE-489 | Active Debug Code | 🟡 MEDIUM | A05:2021 |
| CORS 过度开放 | CWE-942 | Permissive Cross-domain Policy with Untrusted Domains | 🟡 MEDIUM | A05:2021 |
| 目录遍历 | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | 🔴 CRITICAL | A01:2021 |
| 文件上传无限制 | CWE-434 | Unrestricted Upload of File with Dangerous Type | 🟠 HIGH | A04:2021 |
| 错误堆栈泄露 | CWE-209 | Generation of Error Message Containing Sensitive Information | 🟡 MEDIUM | A05:2021 |
| HTTP 安全头缺失 | CWE-693 | Protection Mechanism Failure | 🟡 MEDIUM | A05:2021 |
| SSRF | CWE-918 | Server-Side Request Forgery | 🟠 HIGH | A10:2021 |
| 不安全的直接对象引用 | CWE-667 | Improper Locking | 🟡 MEDIUM | A01:2021 |

## 供应链安全

| 漏洞类型 | CWE-ID | CWE 名称 | 严重程度 | OWASP 分类 |
|---------|--------|---------|---------|-----------|
| 已知漏洞依赖 | CWE-1395 | Dependency on Vulnerable Third-Party Component | 🟠 HIGH | A06:2021 |
| 恶意依赖 | CWE-1395 | Dependency on Vulnerable Third-Party Component | 🔴 CRITICAL | A08:2021 |
| 缺少锁文件 | CWE-1104 | Use of Unmaintained Third Party Components | 🟡 MEDIUM | A06:2021 |
| typosquatting | CWE-1104 | Use of Unmaintained Third Party Components | 🟠 HIGH | A08:2021 |
| 依赖混淆 | CWE-1104 | Use of Unmaintained Third Party Components | 🔴 CRITICAL | A08:2021 |

## 其他常见

| 漏洞类型 | CWE-ID | CWE 名称 | 严重程度 | OWASP 分类 |
|---------|--------|---------|---------|-----------|
| 竞态条件 | CWE-362 | Concurrent Execution Using Shared Resource with Improper Synchronization | 🟠 HIGH | A04:2021 |
| 资源耗尽 | CWE-400 | Uncontrolled Resource Consumption | 🟡 MEDIUM | A04:2021 |
| 整数溢出 | CWE-190 | Integer Overflow or Wraparound | 🟠 HIGH | A04:2021 |
| 空指针解引用 | CWE-476 | NULL Pointer Dereference | 🟡 MEDIUM | A04:2021 |
| TOCTOU | CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition | 🟠 HIGH | A04:2021 |
| 无限循环 | CWE-835 | Loop with Unreachable Exit Condition | 🟡 MEDIUM | A04:2021 |
