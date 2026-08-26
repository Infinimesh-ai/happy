import { runCodex } from '@/codex/runCodex'
import { extractCodexResumeFlag } from '@/codex/cliArgs'
import { extractNoSandboxFlag } from '@/utils/sandboxFlags'
import { ensureDaemonRunning } from '@/daemon/ensureDaemonRunning'
import { resolveSessionNetwork } from '@/iscp/networkStartup'
import type { PermissionMode } from '@/api/types'
import type { ReasoningEffort } from '@/codex/codexAppServerTypes'

export async function handleCodexCommand(args: string[]): Promise<void> {
  let startedBy: 'daemon' | 'terminal' | undefined = undefined
  let permissionMode: PermissionMode | undefined = undefined
  let model: string | undefined = undefined
  let effort: ReasoningEffort | undefined = undefined
  const sandboxArgs = extractNoSandboxFlag(args)
  const codexArgs = extractCodexResumeFlag(sandboxArgs.args)

  for (let i = 0; i < codexArgs.args.length; i++) {
    if (codexArgs.args[i] === '--started-by') {
      startedBy = codexArgs.args[++i] as 'daemon' | 'terminal'
    } else if (codexArgs.args[i] === '--permission-mode') {
      permissionMode = codexArgs.args[++i] as PermissionMode
    } else if (codexArgs.args[i] === '--model') {
      model = codexArgs.args[++i]
    } else if (codexArgs.args[i] === '--effort') {
      effort = codexArgs.args[++i] as ReasoningEffort
    } else if (codexArgs.args[i] === '--yolo') {
      permissionMode = 'yolo'
    }
  }

  // Network mode decision (OPS 2026-08-26 §3.1): legacy credentials keep the
  // existing auth path verbatim; a healthy ISCP profile alone runs ISCP-only.
  // Also fails fast before spawning: a terminal launch without a resolved
  // ISCP profile would be listed by the daemon yet unreachable from the app.
  const network = await resolveSessionNetwork('happy codex', startedBy)
  await ensureDaemonRunning()

  await runCodex({
    network,
    startedBy,
    noSandbox: sandboxArgs.noSandbox,
    resumeThreadId: codexArgs.resumeThreadId ?? undefined,
    permissionMode,
    model,
    effort,
  })
}
