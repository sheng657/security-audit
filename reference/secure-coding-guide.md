# 安全编码规范摘要

> 可落地的安全编码最佳实践，覆盖输入校验、输出编码、密码学、认证授权等核心领域

---

## 1. 输入校验

### 原则

- **白名单优于黑名单**：定义允许的字符/格式，而非试图过滤危险字符
- **服务端校验为主**：前端校验可绕过，必须服务端二次校验
- **长度限制**：所有输入字段设置合理最大长度
- **类型校验**：数字字段只接受数字，邮箱字段正则校验格式

### 实践

```python
# ✅ 正确：白名单校验 + 长度限制
import re

USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,32}$')

def validate_username(username: str) -> bool:
    if not username or len(username) > 32:
        return False
    return bool(USERNAME_PATTERN.match(username))

# ❌ 错误：黑名单过滤
def validate_username_bad(username: str) -> bool:
    dangerous = ["admin", "root", "../", "<script>"]
    for d in dangerous:
        if d in username:
            return False
    return True  # 攻击者可用各种变形绕过
```

```javascript
// ✅ 正确：使用 schema 验证库
const Joi = require('joi');

const userSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(32).required(),
  email: Joi.string().email().required(),
  age: Joi.number().integer().min(0).max(150).required()
});
```

### SQL 查询输入处理

```python
# ✅ 参数化查询（防 SQL 注入）
cursor.execute("SELECT * FROM users WHERE id = %s AND status = %s", (user_id, status))

# ✅ ORM（推荐）
user = User.query.filter_by(id=user_id, status=status).first()

# ❌ 字符串拼接
cursor.execute(f"SELECT * FROM users WHERE id = {user_id} AND status = '{status}'")
```

```javascript
// ✅ 参数化查询
db.query('SELECT * FROM users WHERE id = $1 AND status = $2', [userId, status]);

// ❌ 字符串拼接
db.query(`SELECT * FROM users WHERE id = ${userId} AND status = '${status}'`);
```

---

## 2. 输出编码

### 原则

- **根据输出上下文选择编码方式**：HTML、JavaScript、URL、CSS 上下文各不同
- **默认转义，按需解封**：所有输出默认 HTML entity 编码
- **CSP 兜底**：设置 Content-Security-Policy 头

### 实践

```python
# HTML 输出编码
from markupsafe import escape
html = f"<p>欢迎，{escape(user_input)}</p>"

# JavaScript 上下文编码
import json
script = f"var name = {json.dumps(user_input)};"

# URL 编码
from urllib.parse import quote
url = f"/search?q={quote(user_input)}"
```

```javascript
// React 默认转义（安全）
return <div>{userInput}</div>  // ✅ 自动 HTML 编码

// ⚠️ dangerouslySetInnerHTML 需手动清洗
import DOMPurify from 'dompurify';
return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />;
```

### CSP 配置建议

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';
```

---

## 3. 密码与认证

### 密码存储

```python
# ✅ 使用 bcrypt（推荐）
import bcrypt

# 存储
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# 验证
if bcrypt.checkpw(password.encode(), hashed):
    # 认证成功
    pass

# ✅ 使用 Argon2（更推荐，抗 GPU 破解）
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
ph.verify(hashed, password)

# ❌ 不要使用
import hashlib
hashlib.md5(password.encode())  # MD5 极易被彩虹表破解
hashlib.sha1(password.encode())  # SHA1 也不安全
```

### 密码策略

- 最小 8 位，建议 12 位以上
- 包含大小写字母 + 数字 + 特殊字符
- 禁止常见弱密码（top 10000 列表检查）
- 账户锁定策略：5 次失败后锁定 15 分钟

### JWT 安全

```python
# ✅ 安全的 JWT 使用
import jwt
from datetime import datetime, timedelta

# 使用 RS256（非对称密钥）而非 HS256（对称密钥）
# 密钥从环境变量/密钥管理服务读取
private_key = os.environ['JWT_PRIVATE_KEY']

token = jwt.encode({
    'sub': user_id,
    'iat': datetime.utcnow(),
    'exp': datetime.utcnow() + timedelta(hours=1),
    'iss': 'myapp',
    'aud': 'myapp'
}, private_key, algorithm='RS256')

# 验证
decoded = jwt.decode(token, public_key, algorithms=['RS256'], 
                      issuer='myapp', audience='myapp')
```

```python
# ❌ 不安全的 JWT
token = jwt.encode({'user_id': user_id}, 'hardcoded_secret', algorithm='HS256')
# 问题：密钥硬编码 + HS256 易受密钥爆破
```

---

## 4. 授权与访问控制

### 原则

- **默认拒绝**：所有资源默认需要认证和授权
- **最小权限**：用户/服务只获取完成工作所需的最小权限
- **纵深防御**：多层校验（前端 + API 网关 + 业务层 + 数据层）

### 实践

```python
# ✅ 服务端校验资源归属
@app.get('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)
    if not order:
        abort(404)
    # 关键：校验当前用户是否为订单所有者
    if order.user_id != current_user.id:
        abort(403)
    return jsonify(order.to_dict())

# ❌ 缺少归属校验（IDOR 漏洞）
@app.get('/api/orders/<order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())  # 任何登录用户都能看
```

### RBAC 示例

```python
from functools import wraps

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/admin/users')
@require_role('admin')
def admin_users():
    # 只有 admin 角色可访问
    pass
```

---

## 5. 文件操作安全

### 文件上传

```python
import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    if not file or not allowed_file(file.filename):
        abort(400, '不支持的文件类型')
    
    if file.content_length > MAX_FILE_SIZE:
        abort(400, '文件太大')
    
    # 重命名文件（防止路径遍历和覆盖）
    filename = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    file.save(os.path.join(UPLOAD_DIR, unique_name))
```

### 文件路径安全

```python
import os

# ✅ 安全：使用 os.path.realpath 防止路径遍历
def safe_path(base_dir, user_path):
    real_base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_dir, user_path))
    if not target.startswith(real_base + os.sep) and target != real_base:
        raise ValueError("路径遍历攻击")
    return target

# ❌ 不安全
def unsafe_path(base_dir, user_path):
    return os.path.join(base_dir, user_path)  # 可被 ../../etc/passwd 绕过
```

---

## 6. HTTP 安全头

### 必需的响应头

```python
# Flask 示例
@app.after_request
def set_security_headers(response):
    # 防止点击劫持
    response.headers['X-Frame-Options'] = 'DENY'
    # 防止 MIME 类型嗅探
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS 过滤
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # HSTS（强制 HTTPS）
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # CSP
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    # Referrer 策略
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # 权限策略
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response
```

---

## 7. 日志安全

### 原则

- 记录**什么**发生了，不记录**数据内容**
- 敏感数据（密码、Token、身份证号）脱敏后再记录
- 结构化日志（JSON 格式），便于检索和分析

```python
import logging

logger = logging.getLogger(__name__)

# ✅ 正确：脱敏后记录
def log_login(username, success):
    logger.info("login_attempt", extra={
        'username': username,
        'success': success,
        'ip': request.remote_addr
    })

# ❌ 错误：泄露密码
logger.info(f"用户 {username} 密码 {password} 登录{'成功' if success else '失败'}")

# ❌ 错误：泄露 Token
logger.debug(f"Headers: {request.headers}")  # 可能包含 Authorization: Bearer xxx
```

---

## 8. 依赖安全

### 检查清单

- 使用 lock 文件（`poetry.lock` / `package-lock.json` / `go.sum`）
- 定期运行 `pip-audit` / `npm audit` / `govulncheck`
- 配置 Dependabot / Renovate 自动更新
- CI/CD 中集成安全扫描步骤
- 验证包来源（只从官方源安装）

```bash
# Python
pip-audit                    # 扫描已安装包
safety check                 # 检查 requirements.txt

# Node.js
npm audit                    # 扫描项目依赖
npx better-npm-audit audit   # 增强版

# Go
govulncheck ./...            # Go 官方漏洞检查
```

---

## 9. 错误处理

```python
# ✅ 安全的错误处理
@app.errorhandler(Exception)
def handle_error(e):
    logger.exception("未处理异常")  # 记录完整堆栈到日志
    return jsonify({
        'error': '服务器内部错误',
        'request_id': request_id  # 用于关联日志
    }), 500

# ❌ 不安全：泄露堆栈信息
@app.errorhandler(Exception)
def handle_error_bad(e):
    return str(e), 500  # 攻击者可获取内部路径、版本信息
```
