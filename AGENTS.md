# Agent Workflow

## Sync To Main

When the user says `sync to main` or `synt to main`, they mean:

1. Fetch `origin/main`.
2. Rebase the current branch on `origin/main`.
3. Push the current HEAD directly to `main` with a normal push, for example:
   `git push origin HEAD:main`

Do not force push for this workflow.


## Infini 项目簇协议

本项目属于 **ProjectGroup-2** 簇，协调中枢是 InfiniCenter（唯一事实来源）。

路径锚定：
- 中枢仓库：`../../InfiniCenter`
  （布局若变动，从本项目向上逐级查找含 `clusters.yaml` 的 InfiniCenter 目录）
- 本簇协调目录：`../../InfiniCenter/clusters/ProjectGroup-2/`（下文简称 `<簇>`）

会话开始时：
1. 读 `../../InfiniCenter/clusters.yaml` 确认本项目所属簇，再读 `<簇>/cluster.yaml`
   了解簇全貌。
2. 检查 `<簇>/inbox/Happy/` 是否有未处理信件（archive/ 外的都算），先处理：
   回信写到发件项目的 inbox，处理完移入本项目 inbox 的 archive/。
3. 检查 `<簇>/decisions/` 中 status=proposed 且 affects 包含本项目的决策，
   在其“评审意见”小节追加本项目的意见；中枢级决策
   （`../../InfiniCenter/decisions/C*.md`，改的是协议本身）同样要看。

工作中：
- 修改对外接口/协议前，先查 `<簇>/contracts/` 中涉及本项目的契约；
  改契约必须先在 `<簇>/decisions/` 立案并达成 accepted。
- 影响 >= 2 个项目的变更一律走决策流程，不得私下实施。
- 需要本簇其他项目配合：写对方 inbox
  （`<簇>/inbox/<对方项目>/NNN-来自Happy-<主题>.md`）。
  涉及其他簇、或要改协议本身：立中枢级决策 `../../InfiniCenter/decisions/CNNNN-*.md`。
  若你的 harness 支持跨会话消息且对方会话在线，可额外发消息提速，
  但 inbox 信件不可省略——它是唯一保证送达的通道。

会话结束前：
- 若本次改动对外可见，更新 `<簇>/status/happy.md`。
- 本次会话中达成的跨项目共识必须已落盘到 InfiniCenter（decision / contract /
  inbox / status 之一），否则视为不存在。
