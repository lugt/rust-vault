# Web UI 重构设计：Vue 3 + Naive UI

日期：2026-06-19
状态：待实现

## 背景与动机

当前 web 端 (`web/index.html` + `web/app.js` + `web/app.css` + `web/pkg/`) 是 vanilla JS 单文件实现，功能已齐全（解锁 / 搜索 / CRUD / rekey / history / clear / recover），但存在以下问题：

1. **布局上下堆叠 + 全屏浮层 modal**——操作按钮挤在顶部一条 bar，详情/编辑/历史/清空共用一个全屏遮罩 modal，视觉上不系统化，体验割裂。
2. **维护性差**——390 行单文件 `app.js`，DOM 操作手写、状态散落在全局变量，扩展困难。
3. 用户明确要求：**用 tab 之类的系统化布局**，引入 npm + UI 组件库。

## 目标

- 用 Vue 3 + Naive UI + Vite 重写前端，保留现有 E2E 加密架构与 WASM 加密层不变。
- 布局改为「左侧导航 tab + 右侧主内容区」，条目管理内再分「列表 + 详情/编辑」二级布局。
- 完整覆盖 CLI 的全部操作：搜索、列表、添加、修改、删除、保存、rekey、history、recover、clear。
- 构建为静态文件，scp 到服务器 `/usr/local/erpshared/vault-web`，Nginx 现有 alias 配置无需改动。

## 非目标

- 不改 `vault-wasm` 的导出接口（已满足需求：`unlock` / `all` / `search` / `group_by_*` / `set_entries` / `put_entries` / `rekey`）。
- 不改 `vault-server` 任何端点。
- 不引入路由库（vue-router）——单页 + 内部 tab 切换即可，避免 SPA fallback 路由问题。
- 不做多标签页实时同步。

## 安全不变量（强制）

1. **Master Key 绝不持久化**——只存在 JS 内存（`reactive` 状态），解锁时输入；锁定、关闭页面、60 分钟空闲自动清除。不写入 localStorage / sessionStorage / cookie。
2. **API token 可缓存**——解锁成功后写入 `localStorage`，下次自动回填，减少手动粘贴。token 泄露仅能读取加密密文，无 master key 无法解密，风险可接受。
3. **API URL 可缓存**——同 token，存 localStorage 并支持从当前页面 URL 自动推断。
4. **WASM 加密层保持**——所有加解密在浏览器内完成，master key 不出浏览器。

## 技术栈

- **Vue 3**（`<script setup>` + Composition API）
- **Naive UI**（组件库：布局、表格、抽屉、模态、消息、表单）
- **Vite**（构建，`vite build` 产出 `dist/`）
- **wasm-bindgen / wasm-pack** 产物复用现有 `web/pkg/vault_wasm.js`（Vite 中作为静态资源引入）

## 项目结构

```
web-ui/                      # 新前端根目录（与旧 web/ 并存，验证后替换）
├── package.json
├── vite.config.ts
├── tsconfig.json            # 可选；先用 JS
├── index.html
├── public/
│   └── pkg/                 → 软链或复制自 ../web/pkg/，WASM 产物
└── src/
    ├── main.js              # createApp + naive 注册
    ├── App.vue              # 根：lock screen / main shell 切换
    ├── api.js               # fetch 封装（apiGet/apiPost/apiPut + autoDetectApi）
    ├── store.js             # 全局响应式状态（handle/version/dirty/token/apiUrl）
    ├── wasm.js              # WASM 初始化 + unlock/put/rekey 封装
    ├── components/
    │   ├── LockScreen.vue   # 解锁页（API URL / token / master pw）
    │   ├── AppShell.vue     # 主壳：顶栏 + 侧导航 + <router-view 等价 slot>
    │   ├── TopBar.vue       # 版本/脏标记/锁定按钮
    │   ├── SideNav.vue      # 三个 tab：条目管理 / 历史版本 / 设置
    │   ├── entries/
    │   │   ├── EntriesTab.vue   # 搜索框 + 条目列表
    │   │   ├── EntryDetail.vue  # 详情展示 + 操作按钮
    │   │   └── EntryEditor.vue  # Drawer 抽屉：新增/编辑表单
    │   ├── history/HistoryTab.vue   # 历史列表 + recover
    │   └── settings/SettingsTab.vue # API/token 配置 + rekey + clear
    └── styles.css
```

## 布局

```
┌──────────────────────────────────────────────────────┐
│ 顶部栏  Vault  v2 · 脏:否               [🔒 锁定]      │
├──────────┬───────────────────────────────────────────┤
│ 侧导航    │  主内容区（随 tab 切换）                    │
│ ▸条目管理 │ ┌────────────┬───────────────────────┐   │
│  历史版本 │ │ 搜索 + 列表 │ 详情 / 编辑面板         │   │
│  设置     │ │            │ (name/url/user/pw/note)│   │
│          │ │ [+新增]     │ [✏编辑][🗑删除][💾保存]│   │
│          │ └────────────┴───────────────────────┘   │
└──────────┴───────────────────────────────────────────┘
```

- 顶部固定栏：版本号、脏标记（未保存修改提示）、锁定按钮。
- 左侧导航：三个 tab（Naive `n-menu`）。
- 条目管理 tab：左右二级布局——左侧搜索框 + 条目列表（Naive `n-list` / `n-data-table`），右侧详情面板。
- 新增/编辑：用 Naive `n-drawer`（右侧滑出），不再全屏遮罩，背景仍可操作。
- 历史版本 tab：列表 + 每行「恢复」按钮，recover 前确认。
- 设置 tab：API URL / token 输入并保存、rekey 表单、clear（高危，需输入 CLEAR 确认）。

## 各操作映射

| 操作 | 触发位置 | 实现 |
|---|---|---|
| 搜索 | 条目管理顶部搜索框 | `handle.search(q)`，防抖 200ms |
| 列表 | 条目管理左侧 | `handle.all()` |
| 添加 | 条目管理「+新增」→ Drawer | 表单收集 → `handle.set_entries(append)` → 标脏 → 保存 |
| 修改 | 详情区「✏编辑」→ Drawer | 表单预填 → `set_entries(replace)` → 标脏 → 保存 |
| 删除 | 详情区「🗑删除」 | 确认 → `set_entries(filter)` → 标脏 → 保存 |
| 保存 | 详情区「💾保存」 | `handle.put_entries()` → `PUT /vault` If-Match → 处理 409 |
| rekey | 设置 tab | `handle.rekey(new)` → `POST /vault/rekey` |
| history | 历史版本 tab | `GET /vault/history` |
| recover | 历史版本 tab 每行 | `POST /vault/recover {from_version}` |
| clear | 设置 tab | 输入 CLEAR → `POST /vault/clear` |

## 状态管理

全局状态用一个 `reactive` 对象（`store.js`），不引入 Pinia（YAGNI）：

```js
const state = reactive({
  handle: null,        // VaultHandle (WASM)
  currentVersion: 0,
  dirty: false,
  apiUrl: '',
  token: '',
  masterPw: '',        // 仅内存
  selectedName: null,
  activeTab: 'entries',
});
```

- `apiUrl` / `token` 启动时从 localStorage 回填；`masterPw` 永不持久化。
- 锁定：清空 `handle` / `masterPw` / `selectedName`，`dirty` 提示未保存则确认。
- 空闲 60 分钟自动锁定（复用现有逻辑）。

## 错误处理

- 用 Naive `useMessage` 替代 `alert`，错误以 toast 展示，含 HTTP 状态与 URL。
- 解锁失败区分：网络/CORS、401（token 错）、404（未 init）、解密失败（master key 错）。
- 保存 409 冲突：弹确认是否强制覆盖（refetch → 重新解密 → 应用本地修改 → 重存），逻辑同现有 `app.js`。

## 构建与部署

1. `cd web-ui && npm install`
2. `npm run build` → `dist/`
3. `scp -r dist/* claw@north.anitago.com:/usr/local/erpshared/vault-web/`
4. WASM `pkg/` 一并复制到 `dist/`（Vite `public/pkg/` 或构建后拷贝）。

Nginx 现有配置（`alias /usr/local/erpshared/vault-web/;` + `index index.html`，无 try_files）保持不变即可服务 SPA 单页。

## 迁移策略

- 新前端放 `web-ui/`，旧 `web/` 暂保留作回退。
- 验证通过后，将 `web-ui/dist/*` 部署覆盖 `vault-web/`，旧文件不再使用。
- `web/pkg/`（WASM 产物）被新前端复用，不变。

## 验证清单

- [ ] `npm run build` 产出 `dist/`，本地 `npm run dev` 可解锁、CRUD、rekey、history、recover、clear 全流程。
- [ ] 部署后 `https://claw.anitago.com/keychain/` 全流程通过。
- [ ] Master key 不出现在 localStorage / network / cookie；token 与 apiUrl 可缓存回填。
- [ ] 锁定后内存中无明文条目。
- [ ] 409 冲突、401、404 错误提示正确。

## 开放问题

无。
