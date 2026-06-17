# 密码存储查询服务 — 设计文档

**日期**：2026-06-17
**状态**：待用户复核
**项目目录**：`/home/gtx/Documents/mypass`
**作者**：brainstorming 阶段输出

---

## 0. 摘要

构建一个**自用的密码存储查询服务**：

- 完整 CSV 在客户端加密为一个密文块
- 公网 VPS 暴露 HTTPS 接口，**服务器永远不见明文**（端到端加密）
- 同一份 Rust 核心库 `vault-core` 编译出 CLI、HTTP 服务器、WebAssembly 浏览器客户端
- Nginx 反代终止 TLS，Rust 服务只监听 `127.0.0.1`
- 单人自用，轻量 API token + 强主口令 + 严格 E2E 加密

---

## 1. 总体架构与威胁模型

### 1.1 部署形态

```
[Browser / CLI / 移动端]
    │  HTTPS (TLS 由既有 Nginx 终止)
    ↓
[Nginx :443]  ←  既有 server 配置，本服务仅添加一个 location 块
    │  HTTP (127.0.0.1:8080)
    ↓
[vault-server :8080]  ←  仅 bind 127.0.0.1, 不暴露公网
    │
    ↓
[SQLite: /var/lib/vault/vault.db]
```

Rust 服务**不终止 TLS**，**不持有证书**，**不直接暴露公网**。所有 HTTPS / certbot / 证书续期由用户既有 Nginx 配置处理；本服务只增加一个 `location /keychain/ { ... }` 反代块。

### 1.2 模块划分

```
mypass/  (Rust workspace)
├── crates/
│   ├── vault-core/     # 纯算法库（KDF、AEAD、CEK 包装、CSV 编解码、协议类型、搜索/分类）
│   ├── vault-server/   # axum + SQLite HTTP 服务（无 TLS）
│   ├── vault-cli/      # 命令行客户端
│   └── vault-wasm/     # WASM 构建（喂给 Web 端）
└── web/                # 浏览器 SPA：HTML/JS + 编译后的 WASM
```

`vault-core` 是**单一可信实现源**——CLI、服务器、浏览器共享同一份加密代码。

### 1.3 威胁模型

| 威胁 | 防护 |
|---|---|
| VPS 被入侵，攻击者拿到密文 | E2E 加密 → 无主口令 = 不可解 |
| TLS 中间人 | 强制 TLS 1.3 + HSTS + 证书由 Nginx 持有 |
| 服务器返回伪造/旧版本密文 | `If-Match` 版本号 + 客户端校验 + 拒绝回退 |
| 重放攻击 | 单调递增版本号 |
| 主口令弱 | Argon2id (m=64MiB, t=3, p=1) + 推荐 ≥ 6 diceware 词 |
| 备份泄露 | 密文 + 包装 CEK，缺主口令不可解 |
| 客户端机器被入侵 | 内存中的明文可能泄露（行业普遍接受） |
| 物理访问 VPS | 无防护：攻击者可植入后门。建议全盘加密 + 强物理安全 |
| DoS | Nginx `limit_req` + 防火墙 + 小请求体限制（8MB） |
| 客户端内存 dump | Rust `zeroize` 包装 + `mlock` 防 swap（CLI/服务器端） |

### 1.4 明确不防

- 客户端机器被完全控制（攻击者看到明文）
- 主口令丢失（设计如此，无后门）
- 后量子密码分析（见 §2.4）

---

## 2. 密钥层次与生命周期

### 2.1 密钥派生链

```
主口令 (user-memorized, ≥ 6 diceware 词)
   ↓ Argon2id (m=64 MiB, t=3, p=1, salt=16B 随机)
主密钥 MK (32 bytes)
   ├── HKDF-SHA256("vault:wrap:v1", MK)  →  KEK
   │     └── XChaCha20-Poly1305 包装 CEK → wrapped_cek
   └── HKDF-SHA256("vault:api:v1", MK)   →  auth_key  (未来扩展)

CEK (32 bytes, 随机)
   ↓ XChaCha20-Poly1305
密文 + nonce(24B) + Poly1305 tag(16B)

version (u64, 单调递增)
```

`auth_key` 目前**未使用**——保留扩展位（见 §3.2）。

### 2.2 关键属性

- **MK**：
  - 永不出客户端
  - 派生后驻留内存，`Zeroizing<Vec<u8>>` 包装
  - 60 分钟无活动自动清零（与 §7.5 自动锁定策略一致）
  - CLI/服务器端用 `mlock` 防 swap；WASM 端接受 swap 风险

- **CEK**：
  - 每次 PUT 时**默认重新生成**（前向保密：旧密文无法用新 CEK 重新解开）
  - 客户端本地可选"主口令 + 最新 CEK"加密备份（用于主口令丢失恢复）

- **salt**：
  - 16 字节，初始随机
  - 服务端持久化保存（密文格式里）
  - 主口令变更时**不轮换**（避免密文与 salt 一一对应，便于备份匹配）

### 2.3 主口令变更（rekey）

不重加密 CSV：

1. 客户端用**新主口令**派生新 `MK'`
2. 拉取最新 `wrapped_cek`、解开得 `CEK`
3. 用 `MK'` 重新包装 `CEK` → `wrapped_cek'`
4. `POST /keychain/vault/rekey` body = `{wrapped_cek'}` + `If-Match: <v>`
5. 接受则 `version += 1`

### 2.4 后量子安全

**当前方案对量子计算安全**（Grover 后 128-bit 仍不可行）。明确**不**加 Kyber/ML-KEM：

- 256-bit 对称密钥 + Argon2id = 量子后仍安全
- 真正的威胁是主口令熵（30–50 bit），PQ 帮不上忙
- 等 NIST PQC 标准稳定后再加 hybrid 层

**实际建议**：主口令**至少 6 diceware 词**（~77 bit 熵）。

---

## 3. API 与认证协议

### 3.1 端点

公开路径前缀：`/keychain/`（经 Nginx 反代到本服务的 `127.0.0.1:8080`，内部路径保留 `/vault`）。

| 方法 | 路径 | 用途 | 鉴权 |
|---|---|---|---|
| `GET /keychain/health` | 健康检查 | 公开 |
| `GET /keychain/version` | 服务端版本号 | 公开 |
| `GET /keychain/vault` | 拉取最新 `{wrapped_cek, ciphertext, version, salt}` | Bearer token |
| `PUT /keychain/vault` | 写入新版本，body = 新密文，header `If-Match: <v>` | Bearer token |
| `POST /keychain/vault/rekey` | 仅重包装 CEK（不改 CSV） | Bearer token |

所有 `/keychain/*` 端点经由用户既有 HTTPS 终止。

### 3.2 认证：双层

**第一层（API 鉴权）**：
- `Authorization: Bearer <api_token>` 头
- Token = 64 字节随机（`base64url`），存服务端 `/etc/vault/env` 的 `AUTH_TOKEN`
- 比较用 `subtle::ConstantTimeEq` 防时序攻击
- **目的**：DoS 防护、降低攻击面
- **意义**：API token 泄露 **≠ 数据泄露**（E2E 兜底）

**第二层（E2E 数据保护）**：
- 真正保护来自 MK
- 即使 API token 泄露，攻击者只能拉回无意义密文

**可选第三层**：
- Nginx `allow`/`deny` IP 白名单
- 推荐：限制为自己家庭/移动网络出口 IP

### 3.3 写并发协议（CAS）

```
GET /keychain/vault → version=7
PUT /keychain/vault If-Match: 7  body={...}   → 200 OK, version=8
PUT /keychain/vault If-Match: 7  body={...}   → 409 Conflict
   { current_version: 8, current_wrapped_cek, current_ciphertext, current_salt }
客户端 merge 后重试
```

冲突时返回 409 + 当前服务端状态，客户端自动 merge（按 `name` 去重，**最后写入获胜**或提示人工选择）。

### 3.4 请求/响应格式

```json
{
  "version": 42,
  "salt": "base64url(16B)",
  "wrapped_cek": {
    "nonce": "base64url(24B)",
    "ct": "base64url(48B)"
  },
  "ciphertext": {
    "nonce": "base64url(24B)",
    "ct": "base64url(N + 16B)"
  },
  "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1},
  "created_at": "2026-06-17T10:00:00Z"
}
```

`Content-Type: application/json`，最大请求体 8 MB（防 DoS）。

### 3.5 错误码

| 状态码 | 含义 |
|---|---|
| 200 | 成功 |
| 400 | 请求格式错误 |
| 401 | 鉴权失败（不区分"无 token" vs "错 token"） |
| 404 | 端点不存在 |
| 409 | 版本冲突（CAS 失败） |
| 413 | 请求体过大 |
| 500 | 内部错误（log 详细，response 只说 "internal"） |

---

## 4. 服务器内部实现

### 4.1 技术栈

| 组件 | 选型 |
|---|---|
| HTTP 框架 | `axum` 0.7 + `tower` + `tokio` |
| 数据库 | `rusqlite`（同步，避免 async 复杂度） |
| 加密 | `chacha20poly1305`、`argon2`、`blake3`、`zeroize`、`subtle` |
| 日志 | `tracing` + `tracing-subscriber` |
| 配置 | 环境变量 + `dotenvy` |

`vault-core` 启用 `#![forbid(unsafe_code)]` 与 `#![deny(missing_docs)]`。

### 4.2 关键类型

```rust
// vault-core/src/types.rs
pub struct WrappedCek { /* nonce + ct, 长度强校验 */ }
pub struct EncryptedCsv { /* nonce + ct, AEAD 解密会验证 tag */ }
pub struct Salt([u8; 16]);
pub struct Version(u64);  // newtype, 内部 u64::MAX 饱和
pub struct MasterKey(Zeroizing<[u8; 32]>);
pub struct Cek(Zeroizing<[u8; 32]>);
```

### 4.3 存储（SQLite）

```sql
CREATE TABLE vault (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- 单行
    version INTEGER NOT NULL,
    salt BLOB NOT NULL,             -- 16B Argon2 salt
    wrapped_cek BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    kdf_params BLOB NOT NULL,       -- JSON: {m, t, p, algo}
    created_at TEXT NOT NULL        -- ISO8601
);

CREATE TABLE vault_history (
    version INTEGER PRIMARY KEY,
    salt BLOB NOT NULL,
    wrapped_cek BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    kdf_params BLOB NOT NULL,
    archived_at TEXT NOT NULL
);
-- 历史保留 30 天，用于客户端 merge 后的回滚
```

### 4.4 内存安全

- 所有密钥/明文 buffer 用 `zeroize::Zeroizing` 包装
- CLI/服务器端尝试 `mlock(MCL_FUTURE)` 防止密钥被换出
- WASM 端 `mlock` 不可用，接受 swap 风险

### 4.5 进程

- `bind 127.0.0.1:8080` 强制
- systemd 单元（`vault` 用户，no-new-privileges，ProtectSystem=strict）
- 优雅关闭：SIGTERM → 排空请求 → 关闭 DB

---

## 5. 部署、运维、备份、恢复

### 5.1 服务端部署（不含 Nginx）

TLS / 证书 / Nginx 站点由用户既有架构负责，本服务只增加一个 `location` 块（见 5.2）。

```bash
useradd -r -s /usr/sbin/nologin vault
mkdir -p /var/lib/vault /etc/vault
chown vault:vault /var/lib/vault /etc/vault
chmod 700 /var/lib/vault /etc/vault

cp target/release/vault-server /usr/local/bin/
cp target/release/vault-cli /usr/local/bin/

# systemd 单元（见附录 A）
# /etc/vault/env 包含 AUTH_TOKEN=$(openssl rand -base64 48)
systemctl daemon-reload
systemctl enable --now vault-server
```

**Rust 服务监听**：`127.0.0.1:8080`（仅本机，不暴露公网）。公网访问必须经既有 Nginx。

### 5.2 Nginx 反代片段（用户自行加入既有 server 块）

将以下片段粘贴到既有 `server { ... }` 块内（**不动 TLS / certbot**）：

```nginx
# ===== vault 反代 begin =====
# 注意：以下片段只包含 location 块本身。
# 限流 zone 必须放在 http {} 顶层（不是 server {}），
# 用户需要在 http { ... } 块添加（或确认已有）：
#
#   limit_req_zone $binary_remote_addr zone=vault_api:10m rate=5r/s;
#

# 静态 Web 客户端（如果用户希望在同一站点托管 SPA）
# root 路径需根据实际部署位置调整
# root /var/www/vault/web;
# location = /keychain { return 301 /keychain/; }
# location /keychain/ { try_files $uri $uri/ /keychain/index.html; }

# API 反代（粘贴到既有 server { ... } 块内）
location /keychain/ {
    # 去掉前缀 /keychain/，让 Rust 服务看到 /vault/...
    rewrite ^/keychain/(.*)$ /$1 break;

    # 限流：复用用户在 http{} 里定义的 vault_api zone
    limit_req zone=vault_api burst=10 nodelay;

    proxy_pass http://127.0.0.1:8080;

    proxy_http_version 1.1;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # 防 DoS：限制请求体
    client_max_body_size 8m;

    # 超时
    proxy_connect_timeout 5s;
    proxy_send_timeout    30s;
    proxy_read_timeout    30s;
}
# ===== vault 反代 end =====
```

**用户部署步骤**：
1. 在 `http {}` 块添加 `limit_req_zone $binary_remote_addr zone=vault_api:10m rate=5r/s;`（或确认已有）
2. 把 `location /keychain/ { ... }` 块粘贴到既有 `server { ... }` 块内
3. `nginx -t && nginx -s reload`

**关键点**：
- `rewrite ^/keychain/(.*)$ /$1 break;` 把 `/keychain/vault` 改写为 `/vault` 给 Rust 服务
- `proxy_pass http://127.0.0.1:8080;` 末尾**不带**斜杠，配合上面 rewrite
- `client_max_body_size 8m` 配合 §3.4 的 8MB 上限

### 5.3 首次引导

```bash
# 1. 生成主口令（≥ 6 diceware 词）
# 2. 用 sample.csv 作为 seed
vault-cli init \
  --password "xxxx xxxx xxxx xxxx xxxx xxxx" \
  --token "$AUTH_TOKEN" \
  --api https://vault.example.com/keychain/vault \
  --csv /home/gtx/Documents/mypass/sample.csv
# 流程：生成 salt → 生成 CEK → XChaCha20-Poly1305 加密 sample.csv
#      → MK 包装 CEK → PUT /vault

# 3. 验证
vault-cli get --name "192.168.0.9" --password "..."

# 4. 备份（可选）
vault-cli export-backup --output ~/backup-2026-06-17.json.gpg
```

### 5.4 备份策略

| 层 | 备份什么 | 频率 | 加密 | 保留 |
|---|---|---|---|---|
| 客户端导出 | 整个密文 + 主口令（用户选择） | 每月 | 可选 GPG | 离线 U 盘 |
| 服务端 SQLite | `vault.db` | 每日 | 不再加密（已密文） | VPS 外 + 本地各 1 份 |
| VPS 快照 | 整机 | 每周 | VPS 供应商 | 4 周 |

服务端 SQLite 已经是密文 + 包装 CEK，**只备份此文件即可恢复数据**（前提是主口令没丢）。

### 5.5 灾难恢复

| 故障 | 恢复方法 |
|---|---|
| VPS 挂了 | VPS 快照恢复 |
| 磁盘坏了 | 备份恢复 `vault.db` |
| Nginx 配置坏了 | 恢复既有 Nginx 备份，本服务的 location 块重新粘贴 |
| 主口令忘了 | 没救（设计如此）。客户端导出备份可救 |
| API token 泄露 | 服务端轮换 `AUTH_TOKEN`，重置服务（用旧主口令拉一遍再写回） |
| 主口令弱/被破 | `vault-cli rekey` 重置主口令 + 轮换 CEK |

### 5.6 监控

- `/keychain/health` 端点接入 `healthchecks.io`（cron 监控）
- 关键日志事件：`vault.put`、`vault.get`、`auth.fail`、`version.conflict`
- **不记录** IP（除 X-Forwarded-For 头摘要）、主口令、密文、版本

---

## 6. 测试与质量保证

### 6.1 测试金字塔

```
        ┌─────────────────┐
        │   端到端测试     │  真实 Nginx + 自签证书
        └────────┬────────┘
       ┌─────────┴──────────┐
       │   集成测试          │  axum TestServer + 真实 SQLite
       └────────┬───────────┘
    ┌───────────┴────────────┐
    │  单元测试              │  vault-core 每个模块
    └────────────────────────┘
```

### 6.2 单元测试（`vault-core`）

- KDF：相同 salt 派生结果相同、不同 salt 不同
- AEAD round-trip
- AEAD 篡改密文失败（wrong tag）
- AEAD 错 key 失败
- AEAD 错 nonce 失败
- `WrappedCek` 长度校验
- CSV codec：unicode、引号转义、空字段
- `zeroize` 真的清零（借 `mprotect`）
- WASM target 同样跑一遍

### 6.3 集成测试（`vault-server`）

- `GET /vault` 返回最新
- `PUT /vault` 带正确 `If-Match` 成功
- `PUT /vault` 带错误 `If-Match` 返回 409 + 当前状态
- `POST /vault/rekey` 仅更新 `wrapped_cek`
- 缺失/错误 token 返回 401
- 请求体超过 8MB 返回 413
- 注入测试：`If-Match` 头含 SQL 注入字符返回 400

### 6.4 端到端测试（shell）

- 在本地启动 Rust 服务（无 Nginx），用 `vault-cli` 跑完整 init → get → add → put → 冲突 → rekey 流程
- 在用户 VPS 上：复用既有 HTTPS 站点，新增 location 块后跑一遍上述流程，验证 `/keychain/` 反代
- 验证：客户端解密结果与原 CSV 字节级一致

### 6.5 安全测试

- **已知答案测试**（KAT）：Argon2id 用 RFC 测试向量
- **差分测试**：与 `libsodium` / `openssl` 同样输入对比输出
- **模糊测试**（`cargo-fuzz`）：CSV codec 和 HTTP 解析器
- **Miri**：检测未定义行为
- **依赖审计**：`cargo audit`、启用 `#![forbid(unsafe_code)]` 在 `vault-core`
- **静态分析**：`cargo clippy --all-targets -- -D warnings`

### 6.6 CI

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test --all
      - run: cargo audit
```

### 6.7 性能基准

- Argon2id (64MiB, t=3) ~ 200ms
- XChaCha20-Poly1305 加解密 1MB ~ 5ms
- GET /keychain/vault 1k 行密文（~500KB）网络 < 200ms
- PUT /keychain/vault 1k 行明文加密+上传 ~ 500ms

---

## 7. Web 客户端：搜索、分类、模糊匹配

### 7.1 规模假设

1k–3k 行，**全部在浏览器内存中**（解密后），客户端做任何算法都不影响安全模型。

### 7.2 数据模型（在 CSV 上加一层逻辑视图）

原始 CSV：`name, url, username, password, note`（保持不变，向后兼容）。客户端在内存里派生：

```rust
struct Entry {
    name: String,        // 来自 CSV
    url: String,
    username: String,
    password: String,
    note: String,
    domain: String,      // 从 url 提取：url::Url::host_str()
    tags: Vec<String>,   // 从 note 解析（约定 #tag）
    modified_at: Option<String>,  // 未来从 CSV 加列；现在为 None
}
```

**`tags` 解析规则**：`note` 字段中以 `#` 开头的 token（如 `#work #email`）作为标签。
**`domain` 提取**：`url::Url::parse().host_str()`，失败时回退到原 url。

### 7.3 搜索架构

#### 7.3.1 搜索管道

```
用户输入查询字符串 Q
    ↓
分词：按空白拆词
    ↓
对每行 E 计算 4 字段分项分数
    ↓
加权求和 → 总分
    ↓
阈值过滤 + 排序
```

#### 7.3.2 匹配算法

| 字段 | 算法 | 权重 |
|---|---|---|
| `name` | trigram 相似度（≥ 0.5）+ 子串命中加成 | 0.40 |
| `url` / `domain` | trigram 相似度 + 子串命中 | 0.25 |
| `username` | trigram 相似度 + 子串命中 | 0.20 |
| `note` | 子串命中 + tag 命中加成 | 0.15 |

**trigram 相似度** = `|Q.trigrams ∩ E.trigrams| / |Q.trigrams ∪ E.trigrams|`（Jaccard）。
计算前对查询串和目标字符串**统一 lowercase + Unicode 归一化（NFC）**。

**子串加成**：如果 Q 是 E 任一字段的子串，加 `+0.3` 到该字段分（截断到 1.0）。

**总分** = 加权求和，> 0.15 视为命中。
**例**：`Q="githb"`，`E.name="github"`：
- trigrams Q = {git, ith, thb}（3 个），trigrams E = {git, ith, thu, hub}（4 个）
- 交集 2，并集 5，Jaccard = 0.4
- 子串检查：`"githb" in "github"` = false
- name 字段分 = 0.4 × 0.4 = 0.16 ≥ 0.15 ✓ 命中
- 仅当用户搜索 `name:` 才加权（其他字段权重更低、可能不命中 → 接受）

**为何不用 fuse.js / uFuzzy**：
- 1k–3k 行规模下，纯 Rust 实现 trigram 仅 ~200 行
- `vault-core` 已经定义，浏览器 WASM 自动获得
- 避免额外 JS 依赖、bundle 体积更小
- **不**实现 Damerau-Levenshtein（O(n*m) 慢，trigram 已足够）

**支持多词 AND**：用户输入 `github email`，两词都必须命中（同一字段或跨字段），用于缩小范围。
- 跨字段允许：`name` 命中 `github`、note 命中 `email` → 整行 AND 通过
- 字段权重重算：每词贡献 = 该字段最高匹配 × 权重，所有词的贡献**乘积**作为最终分（保守 AND）

#### 7.3.3 性能预算

- 1k 行：单次查询 < 5ms（trigram 预计算存 `HashMap<Vec<u8>, u32>`）
- 3k 行：单次查询 < 15ms
- 每次解密后**一次性**预计算所有行的 trigram，搜索只做集合运算

### 7.4 分类（分组）

#### 7.4.1 自动按域名分组（默认）

```
github.com          → "代码托管"
google.com          → "搜索引擎"
mail.google.com     → "搜索引擎"（取 eTLD+1）
192.168.0.9         → "内网 / 设备"
```

**实现**：
- 简单字典映射（小库 `~/.vault/domains.json`，用户可编辑）
- 未知域名 → 落到 "其他" 桶
- IP 地址（IPv4/IPv6）→ 自动归到 "内网 / 设备"

#### 7.4.2 按 tag 分组

note 字段里 `#` 开头的 token 解析为 tag。点击 tag 即按 tag 过滤。

#### 7.4.3 按首字母（A-Z / 0-9）分组

经典通讯录式分组，兜底视图。

#### 7.4.4 分类 UI

左侧侧边栏：

```
📁 全部 (1234)
🏷 工作 (89)
🏷 个人 (203)
🏷 邮箱 (45)
🌐 代码托管 (12)
🌐 银行 (8)
🔌 内网 / 设备 (6)
❓ 其他 (871)
🔤 A-Z
⭐ 收藏
🕒 最近修改
```

每个分类项带计数（实时统计）。

### 7.5 UI 组件

| 组件 | 功能 |
|---|---|
| **搜索框** | 实时搜索（输入即查，200ms debounce），支持 `key:term` 过滤（`name:github`、`tag:work`） |
| **分类侧栏** | 见 7.4.4 |
| **结果列表** | 按相关度降序，匹配字段加 `<mark>` 高亮 |
| **详情面板** | 选中行后右侧显示完整字段、密码（默认遮罩，点击显示） |
| **复制按钮** | 一键复制密码/用户名，**30 秒后自动从剪贴板清除**（`navigator.clipboard.writeText` + setTimeout） |
| **编辑/新增按钮** | 触发模态框，编辑后调用 `PUT /keychain/vault` |
| **冲突对话框** | 收到 409 时弹出，显示服务端当前版本，merge 工具 |
| **主口令提示** | 首次访问要求输入主口令；60 分钟不活动自动锁定（清内存） |

### 7.6 模糊匹配 vs 精确匹配 UX

- **默认模糊**：拼写错误、缩写（`githb` 匹配 `github`）能容忍
- **精确模式**：在搜索词两端加双引号 `"github com"`，**只**匹配子串，关闭 trigram
- **正则模式**：以 `/` 开头视为 JS 正则（高级用户）

### 7.7 跨平台一致性

搜索/分类逻辑在 `vault-core` 实现，**CLI 与 Web 共用**：

```bash
# CLI 等价
vault-cli search "github"
vault-cli search "name:git tag:work"
vault-cli group-by domain
```

这样 CLI、桌面端、移动端、Web 端搜索结果完全一致。

### 7.8 内存中数据生命周期

```
主口令输入 → Argon2id → MK
    ↓ 解开 wrapped_cek → CEK
        ↓ 解密 ciphertext → CSV 字节
            ↓ 解析为 Vec<Entry>
                ↓ 预计算 trigram 索引
                    ↓ 渲染 UI
```

- 60 分钟无活动 → **自动锁定**（清空 `Vec<Entry>`、MK、CEK；trigram 索引随之失效）
- 浏览器关闭 → 自动清空（无持久化）
- 不写 `localStorage`：主口令、CEK、解密后的密码**永不**下盘
- API token 单独可放 `localStorage`（仅 API 鉴权，泄露 ≠ 数据泄露）

---

## 8. 实施计划

详细分步实施计划由 `writing-plans` 技能生成（见附录 B）。

粗略里程碑：

1. **M1（核心库）**：`vault-core`（含搜索/分类）单元测试齐全，差分测试通过
2. **M2（服务器）**：`vault-server` 集成测试齐全，本地 e2e 通过
3. **M3（CLI）**：`vault-cli` 完成 init/get/put/rekey/search/group
4. **M4（部署）**：VPS 上 systemd + 既定 Nginx location 块跑通（用户提供 location 片段）
5. **M5（Web）**：`vault-wasm` + 浏览器 SPA（搜索框、分类侧栏、详情面板、复制），主流程跑通
6. **M6（硬化）**：安全审计、依赖审计、文档

---

## 附录 A：systemd 单元

```ini
[Unit]
Description=Vault server (E2E password store)
After=network.target

[Service]
Type=simple
User=vault
Group=vault
WorkingDirectory=/var/lib/vault
EnvironmentFile=/etc/vault/env
ExecStart=/usr/local/bin/vault-server
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/vault
LimitNOFILE=65536
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

## 附录 B：交付物清单

- [ ] `crates/vault-core/` — 加密核心库（含搜索/分类）
- [ ] `crates/vault-core/src/search.rs` — trigram 搜索 + 评分
- [ ] `crates/vault-core/src/group.rs` — 按域名/tag/首字母分组
- [ ] `crates/vault-server/` — HTTP 服务
- [ ] `crates/vault-cli/` — CLI 客户端（init/get/put/rekey/search/group）
- [ ] `crates/vault-wasm/` — WASM 包
- [ ] `web/` — 浏览器 SPA
  - [ ] 搜索框（实时、key:term 语法、模糊/精确/正则切换）
  - [ ] 分类侧栏（域名桶、tag、首字母、收藏、最近）
  - [ ] 详情面板
  - [ ] 复制按钮（30s 自动清剪贴板）
  - [ ] 编辑/新增模态框
  - [ ] 冲突 merge 对话框
  - [ ] 自动锁定（60 分钟无活动）
- [ ] `docs/DEPLOY.md` — 部署指南
- [ ] `docs/THREAT_MODEL.md` — 威胁模型文档
- [ ] `.github/workflows/ci.yml` — CI
- [ ] `systemd/vault-server.service` — systemd 单元
- [ ] `nginx/vault.conf.snippet` — Nginx 反代片段（用户粘贴到既有 server 块）
