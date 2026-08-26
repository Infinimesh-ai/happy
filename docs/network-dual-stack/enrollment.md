# 双栈改造 · ISCP Enrollment / Credential Handoff 设计（Phase 0）

状态：已冻结。映射到 ISCP v2 Provisioning 规范
（`spec/provisioning.md`、`spec/trust-root.md`，pin 的上游 commit 见 `packages/iscp`）。

## 1. 边界声明（不可协商）

- **ITES token、ITES SDK、Cloud admin client、手机私钥永不进入 Happy 代码与存储。**
- 跨越 App/Cloud → Happy 边界的唯一产物是 **Pairing Ticket**（一次性、短时效）。
- Happy 侧只理解：Pairing Ticket、本机 Ed25519 设备身份、Local Secure Channel、
  Provisioning Bundle、Trust Grant。资格审批（谁有权批准 Happy 节点）完全发生在
  App ↔ Cloud 控制面，Happy 不感知。
- Happy daemon / Happy App 各自是独立 ISCP 设备（独立密钥对），不借用任何其他设备身份。

## 2. 流程（映射 ISCP Provisioning 状态机）

```
Cloud（已由 JingSi App 完成资格批准）
  │ 签发 Pairing Ticket
  ▼
入口三选一 ──────────────────────────────┐
  A. App 扫 QR（复用现有相机流程）        │
  B. 深链 happy://iscp-enroll?ticket=…    │ ticket_issued
  C. CLI: happy iscp enroll <短码>        │
  ▼                                      │
Happy 设备本地生成 Ed25519 身份（私钥永不出设备）
  │ 凭 ticket 联系 Trust Root            │ ticket_consumed
  ▼
Local Secure Channel：临时 X25519 密钥协商 + OOB 短码核对
  （Happy 显示短码，用户在 Cloud/App UI 侧核对确认）
  │                                      │ local_channel_ready
  ▼        ── 规则：凭据/grant 严禁在 local_channel_ready 之前传输 ──
Provisioning Bundle 经安全通道下发        │ bundle_sent
  { device_id, domain_id, trust_root 信息, relay 发现提示, 初始 Trust Grant }
  │ Happy 校验签名、持久化               │ bundle_applied
  ▼
创建 HappyNetworkProfile{ mode:'iscp', deviceId, domainId, credentialRef }
```

`bundle_applied` 后的一切连接（Relay WS、Session Hello/Ready、credential 轮换/撤销）
只依赖设备私钥 + Trust Grant，与 enrollment 入口无关。

## 3. 各端实现落点

| 端 | 落点 | Phase |
|---|---|---|
| CLI | `packages/happy-cli/src/iscp/enrollment.ts` + `happy iscp enroll <ticket|短码>` 命令：打印 OOB 核对码，`bundle_applied` 后写 `~/.happy/iscp/<profileId>/` | 2 |
| App | `@slopus/iscp` 暴露 enrollment API；设置页"通过 ISCP 连接"入口：QR 扫码/粘贴 ticket → OOB 码确认 → 建 profile | SDK: 2，UI: 3 |
| SDK | `packages/iscp/src/provisioning/`（pairingTicket / localSecureChannel / bundle） | 2 |

## 3.1 旧 `pair_…` 人工配对码：Happy 已弃用（OPS 2026-08-26 §3.4）

Cloud 早期 `/v1 pairing-tickets` + `register-with-ticket{pairing_code}` 的 `pair_…`
人工注册码不是 Happy enrollment 输入。`happy iscp enroll` 收到 `pair_` 前缀时抛出
稳定错误码 **`legacy_pairing_code_unsupported`**（`src/iscp/enrollment.ts`
`LegacyPairingCodeError`），附迁移提示（向 Console/JingSi 索取签名的
`iscp.pairing_ticket.v2` ticket 或 wrapper），且**不消费旧码**、不把原码回显进错误
文案。通用 base64 解码错误（`invalid enrollment payload encoding`）保留给真正的
编码损坏输入。Cloud 侧的旧码 deprecated 标记、指标与分期下线见 OPS 交接 §3.4，
Happy 不参与旧协议兼容。

## 4. 失败与安全语义

- ticket 过期/已消费 → Trust Root 拒绝，Happy 报 `unauthorized`，不留任何状态；
- OOB 短码不匹配 → 用户取消，通道废弃，重新走 ticket；
- bundle 签名校验失败 → 丢弃并报错，绝不部分应用；
- enrollment 中途断开 → 从 ticket 阶段重来（ticket 一次性，需 Cloud 重发）；
- 撤销：Trust Root revoke（grant `revocation_epoch` 递增 + revocations feed）→
  Happy 侧 transport 报 `unauthorized`，本地 profile 由用户显式删除（`wipeProfile`），
  互不影响 legacy 账号（见 inventory.md §3.3）。

## 5. 独立 Happy App 直接发起资格申请（Phase 4+，只留缝）

若未来独立 Happy App 需要自己发起 Cloud 资格申请：由宿主登录组件或外部浏览器完成
ITES 登录与审批，最终仍只把 Pairing Ticket 交给 Happy——本文件的流程不变，
Happy 内部不新增任何 ITES 依赖。
