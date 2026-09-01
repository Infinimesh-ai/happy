# 双栈改造 · 网络触点盘点与 Namespace 方案（Phase 0）

状态：已冻结。对应实施计划 Phase 0 交付物；后续 Phase 修改本文件需在 PR 中说明。

关联文档：[enrollment.md](./enrollment.md) ·
需求来源：`happy-iscp-dual-stack-plan.md`（Happy 原有网络 / ISCP 双栈改造方案）

## 0. 已冻结的决策

| # | 决策 | 结论 |
|---|---|---|
| 1 | 实施范围 | Phase 0–3；Phase 4（JingSi App 内嵌）/ Phase 5（灰度运营）只留接口缝 |
| 2 | ISCP TS 客户端 | monorepo 内新建 `packages/iscp`，按 ISCP v2 JSON Schema + OpenAPI 从规范实现（上游为纯 Go 参考实现，pin commit SHA） |
| 3 | 离线/历史模型 | **daemon 为唯一历史源**：会话历史落在 agent 机器的事件日志，App 按 cursor 拉取补齐；Relay 只做在线投递 + 短 TTL 离线队列；无服务器持久化密文 |
| 4 | Payload protection | 仅 `iscp_session_v1`（ISCP 会话 ChaCha20-Poly1305 单层 E2E）；ISCP 模式无 Happy 内层加密 |

概念映射备忘（方案文档词汇 → ISCP 实际词汇）：Cloud ≈ Trust Root（+生态外围）；
enrollment ≈ Provisioning（Pairing Ticket → Local Secure Channel → Provisioning Bundle）；
`agent.capability.v1` 为 Happy 层 payload 约定（ISCP 本身无 capability 协商层）。
ITES / ConnectionHub 是 App→Cloud 控制面概念，**永不进入 Happy 代码**。

## 1. happy-app 网络触点分类

分类定义：

- **core** — 双模式都必须工作，走 `HappyTransport` 端口；
- **legacy-only** — 依赖 happy-server 的社交/增值能力，ISCP 模式下不启动、UI 隐藏（`useProfileCapability('legacy-social')`，Phase 3 接线）；
- **replaced** — ISCP 模式下由其他机制取代。

### 1.1 core（走 transport 端口）

真正的 socket 消费方只有两个文件（`getHappyClientId` 纯辅助函数不算网络触点）：

| 文件 | 引用 | 使用的 apiSocket 面 |
|---|---|---|
| `sources/sync/ops.ts` | 30 处 | `sessionRPC`×12、`machineRPC`×12（spawn/fork/rewind/权限/文件/bash 等） |
| `sources/sync/sync.ts` | 13 处 | `initialize`、`request`(HTTP `/v1/sessions`、`/v3/messages` 等)、`onMessage('update'\|'ephemeral')`、`onStatusChange`、`onReconnected`、`sendAppState`、`emitWithAck` |

对应的 transport 方法注册表（Phase 1 起）：

| wire method | Legacy 实现 | ISCP 实现（Phase 3） |
|---|---|---|
| `sessions.list` | HTTP `GET /v1/sessions` | daemon `sessions.list` |
| `messages.pull` | HTTP `GET /v3/sessions/:id/messages` | daemon 事件日志 cursor 拉取 |
| `messages.send` | 现有 outbox → `POST /v3` | daemon `messages.send{localId}` |
| `session.rpc` / `machine.rpc` | `emitWithAck('rpc-call')` + 现有加密 | SecureEnvelope 请求/响应 |
| `http`（兜底） | `apiSocket.request()` | 不支持（`unsupported`） |

### 1.2 legacy-only（ISCP 模式优雅降级）

`sources/sync/` 下：`apiFeed.ts`、`apiFriends.ts`、`apiGithub.ts`、`apiKv.ts`、
`apiVoice.ts`、`apiUsage.ts`、`apiServices.ts`、`apiArtifacts.ts`；
以及 `gitStatusSync.ts`、`apiAttachments.ts`（raw `fetch` 直连 happy-server 的
上传/下载 URL）。`realtime/`（语音）依赖 apiVoice，同为 legacy-only。

`auth/` 全部（authGetToken、authQRStart/Wait、authApprove、authAccountApprove、
secretKeyBackup）：Legacy 账号体系专属，ISCP 模式用 enrollment 取代（见 enrollment.md）。

产品语义：ISCP profile 激活时这些模块的 sync 任务不启动、入口 UI 隐藏。这是**接受的
产品降级**，不做兼容层。

### 1.3 replaced（ISCP 模式另行取代）

| 触点 | Legacy | ISCP 模式 |
|---|---|---|
| 消息历史拉取 | HTTP `/v3/sessions/:id/messages` | daemon 事件日志 `messages.pull{afterCursor}` |
| push 注册（`apiPush.ts`、`pushRegistration.ts`） | happy-server push | **Phase 0–3 无 push**（显式缺口，见 §4） |
| 登录/账号恢复 | master secret + token | Pairing Ticket enrollment |
| E2E 加密（`sync/encryption/`） | master secret / dataEncryptionKey | `iscp_session_v1`（transport 层保护，摄入路径无解密） |

## 2. happy-cli 网络触点

| 文件 | 角色 | 双栈处理 |
|---|---|---|
| `src/api/apiSession.ts` | 每会话进程的 session-scoped socket + outbox | **加 tee**：ISCP 模式（`HAPPY_NETWORK_PROFILE` 环境变量）outbox 发往 daemon 控制通道，legacy 原样；**ISCP-only 模式**（token=null）完全不建 socket/HTTP，见 §2.1 |
| `src/api/apiMachine.ts` | daemon 的 machine-scoped socket + RPC handlers | ISCP 模式不连 happy-server；`RpcHandlerManager` 方法名被 `wireResponder` 1:1 桥接 |
| `src/api/api.ts`、`auth.ts`、`webAuth.ts`、`pushNotifications.ts` | HTTP/认证/push | legacy-only；ISCP-only 模式下不构造、不调用 |
| `src/daemon/controlServer.ts` | localhost fastify 控制面 | 扩展 `POST /iscp/session-event`（Phase 3） |
| `src/daemon/run.ts` | daemon 主循环、spawnSession | ISCP 模式下持有 `IscpPeer`（每机器单设备，会话进程不触 ISCP）；启动前先做 §2.1 网络模式决策 |
| `src/iscp/networkStartup.ts` | **网络模式决策**（OPS 2026-08-26 §3.1/§4.1） | 会话入口（claude/codex）与 daemon 共用；决策纯函数可测 |

历史现状：本地只有 agent 原生 transcript（Claude JSONL）与 `~/.happy/sessions.json`；
**daemon 事件日志是新建物**（`src/iscp/eventLog.ts`，Phase 3）。

### 2.1 ISCP-only 独立运行（OPS 2026-08-26 §3.1/§4.1，已实现）

Legacy 与 ISCP 是并列网络身份，不是"legacy 登录后的插件"。启动决策矩阵
（`src/iscp/networkStartup.ts`，`decideSessionNetwork` / `decideDaemonNetwork` 纯函数钉测试）：

| legacy 凭据 | ISCP profile 解析 | 会话 (`happy` / `happy codex`) | daemon |
|---|---|---|---|
| 有 | 有（显式或唯一健康自动选） | dual-stack：legacy auth 逐字保留 + tee | legacy 启动逐字保留 + ISCP peers |
| 有 | 无 / 显式 `''` | legacy，原样 | 同上 |
| 无 | 有 | **ISCP-only**：不读/不建 legacy 凭据，无交互登录 | **ISCP-only**：跳过 auth/machine 注册/Server socket |
| 无 | 注册了但全不健康 | fail-fast + 修复指引（不落 QR 登录） | fail-fast + 修复指引 |
| 无 | 无 | 模式选择引导（TTY 选择器 / headless 报错），显式 `''` 视为选定 legacy | fail-fast + 双向指引 |

ISCP-only 会话（`ApiSessionClient` token=null + `src/iscp/iscpOnlySession.ts` 本地铸造
session id/key）各面的明确实现——不是通用 no-op stub：

- **history**：tee → daemon 事件日志（与 dual-stack 相同路径）；`flush()` 排空 tee；
- **user message / session RPC**：localhost session RPC server（daemon wireResponder 桥接），
  `close()` 停 server 与心跳；
- **metadata / agentState**：本地版本计数 + 每次变更重发 `/session-started` webhook
  （daemon 端 `sessions.list` 展示与 resume-in-place 环境依赖它）；
- **keepAlive / death**：显式 no-op —— 活性 = session RPC 心跳 + daemon 子进程表，
  退出由 daemon 观测并发 session-lifecycle；
- **resume-in-place**：daemon 持久化的本地 key/版本经 `HAPPY_RECONNECT_*` 原样恢复；
- **legacy-only 降级面（显式拒绝或记录后跳过）**：附件 blob、push 通知、server 端
  usage 聚合、agentState 的手机可见性（权限请求 UI）——等 ISCP 状态通道另行立项。

legacy-only agent（gemini/acp/openclaw/agy）在 ISCP-only 主机上明确报 unsupported，
不落交互登录（`ensureLegacyOnlyAgentUsable`）。

## 3. Namespace 与登出契约（冻结）

Profile 是身份、存储 namespace 和登出的最小单元（类型见
`packages/happy-wire/src/transport.ts` 的 `HappyNetworkProfile`）。

### 3.1 happy-app

| 存储 | legacy-default（现有用户） | ISCP profile |
|---|---|---|
| 凭据 | SecureStore/localStorage key `auth_credentials`（**原位不动，零迁移**） | SecureStore key `iscp_device_<profileId>`（设备私钥 + credential ref） |
| 缓存 MMKV | 现有默认实例（未命名空间，**原位不动**） | 每 profile 独立实例 `cache-<profileId>` |
| profile 注册表 | 独立 MMKV 实例 `happy-profiles`（新增；首启从 `auth_credentials` 合成 `legacy-default`） | 同左 |
| server 配置 | 现有 `server-config` MMKV 实例（登出后存活，维持现状） | 不适用（relay 由 Provisioning Bundle 提供） |

### 3.2 happy-cli

| 存储 | legacy | ISCP |
|---|---|---|
| 凭据/设置 | `~/.happy/`（access.key、settings.json 等，原位不动） | `~/.happy/iscp/<profileId>/`：`device.key`(0600)、`bundle.json`、`replay-state.json` |
| 事件日志 | 无（服务器持久化） | `~/.happy/iscp/<profileId>/sessions/<sessionId>/log.jsonl` + `meta.json{lastSeq,epoch}` |

### 3.3 登出/撤销契约（验收标准）

1. `wipeProfile(id)` 只擦除该 profile 的 namespace：其 MMKV 实例、其 SecureStore
   key、内存中的 session key，并 `close()` 其 transport；
2. 登出 legacy-default 走**现有逐字保留的路径**（clearPersistence + 删 `auth_credentials`），
   不触碰 `~/.happy/iscp/*`、`iscp_device_*`、`cache-*`；
3. 撤销 ISCP 设备（Trust Root revoke 或本地删除 profile）不触碰 `auth_credentials`
   与默认 MMKV 实例；
4. 切换 profile = 关旧 transport → 清内存密钥 → 起新 transport，无并存连接；
5. 一个 profile 永不同时含 legacy token 和 ISCP credential（类型层已由判别联合保证）；
6. telemetry 只允许携带 `mode` 标记，禁止 token、session key、消息明文
   （`@slopus/iscp` 包内禁止打印密钥材料，envelope 日志脱敏，grep 式测试兜底）。

## 4. 显式缺口（接受并记录）

- **ISCP 模式无 push**（Phase 0–3）：Relay 无 push 通道。前台按 cursor 补拉保证正确性，
  短 TTL relay 队列覆盖短暂后台。`wireResponder` 预留 `wakeup.v1` 钩子点，
  供 Phase 4/5 接 Cloud 唤醒端点（data-only、零业务内容）。
- **daemon 离线即无历史**：决策 3 的固有属性。UI 明示"机器离线"，不做假缓存掩盖。
- **legacy-only 功能在 ISCP 模式不可用**：feed/friends/github/voice/kv/usage/附件直传。

## 5. happy-server

零改动。Legacy 路径原样；ISCP 路径完全绕过 happy-server。
