/**
 * Regression (OPS 2026-08-17 rollout log §7.3, defect 1): `happy --version`
 * and `happy --help` are pure queries and must have ZERO runtime side
 * effects. The version branch used to fall through into the normal startup
 * flow "to pass --version to Claude Code"; under fail-fast ISCP profile
 * resolution that auto-selected the single healthy profile and briefly
 * bootstrapped a real Agent session, so install/version probes created
 * short-lived sessions in production.
 *
 * These tests run the REAL CLI entry (dist/index.mjs, built by the vitest
 * global setup) inside a scratch HAPPY_HOME_DIR that is rigged to make any
 * fall-through observable:
 *  - a live-looking daemon.state.json points at a recording HTTP server
 *    (any daemon contact / auth server call is a failure);
 *  - an enrolled-but-corrupt ISCP profile is planted (profile resolution
 *    would print its loud "none is healthy" warning);
 *  - the home dir is checked afterwards for session artifacts;
 *  - the unauthenticated flow's interactive auth prompt must never appear.
 */

import { spawnSync, type SpawnSyncReturns } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

import packageJson from '../package.json'
import { projectPath } from './projectPath'

const cliEntry = join(projectPath(), 'dist', 'index.mjs')

describe('version/help queries are side-effect free', () => {
  let server: Server
  let port: number
  let home: string | null = null
  const recordedRequests: string[] = []

  beforeAll(async () => {
    server = createServer((req, res) => {
      recordedRequests.push(`${req.method} ${req.url}`)
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ children: [] }))
    })
    port = await new Promise<number>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        resolve((server.address() as { port: number }).port)
      })
    })
  })

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  afterEach(() => {
    if (home !== null) {
      rmSync(home, { recursive: true, force: true })
      home = null
    }
  })

  const runCli = (args: string[]) => {
    recordedRequests.length = 0
    home = mkdtempSync(join(tmpdir(), 'happy-query-probe-'))
    // A live-looking daemon: pid is this (alive) test process, port is the
    // recording server. If the CLI ensures/contacts the daemon in any way,
    // the recorder sees the request.
    writeFileSync(join(home, 'daemon.state.json'), JSON.stringify({
      pid: process.pid,
      httpPort: port,
      startTime: new Date().toLocaleString(),
      startedWithCliVersion: '0.0.0-not-this-build',
    }))
    // An enrolled-but-corrupt ISCP profile: profile resolution classifies it
    // as unhealthy and prints a loud warning — which a pure query must never
    // reach.
    mkdirSync(join(home, 'iscp', 'probe-profile'), { recursive: true })
    writeFileSync(join(home, 'iscp', 'probe-profile', 'bundle.json'), 'not json — corrupt on purpose')
    return spawnSync(process.execPath, [cliEntry, ...args], {
      encoding: 'utf8',
      timeout: 60_000,
      env: {
        ...process.env,
        HAPPY_HOME_DIR: home,
        // Neutralize any ambient profile pin: resolution must not run at all.
        HAPPY_NETWORK_PROFILE: undefined,
        // Paranoia: even a regression must never reach a real backend.
        HAPPY_SERVER_URL: `http://127.0.0.1:${port}`,
        HAPPY_WEBAPP_URL: `http://127.0.0.1:${port}`,
      },
    })
  }

  const expectNoRuntimeSideEffects = (result: SpawnSyncReturns<string>) => {
    // The daemon (and the server URL, which points at the same recorder)
    // must never have been contacted.
    expect(recordedRequests).toEqual([])
    // Profile resolution must never have run: the planted corrupt profile
    // would have produced the "profiles are enrolled ... none is healthy"
    // warning on stderr.
    expect(result.stderr).not.toContain('ISCP')
    expect(result.stderr).not.toContain('profile')
    // The unauthenticated startup flow must never have been entered: it
    // renders an interactive auth prompt.
    expect(result.stdout).not.toContain('authenticate')
    // No artifacts beyond what we planted and the logs dir the configuration
    // layer eagerly creates: no settings migration, no sessions.json, no
    // eventlog session directories, no profile locks.
    const entries = readdirSync(home!).sort()
    expect(entries.filter((entry) => !['daemon.state.json', 'iscp', 'logs'].includes(entry))).toEqual([])
    expect(existsSync(join(home!, 'settings.json'))).toBe(false)
    expect(existsSync(join(home!, 'sessions.json'))).toBe(false)
    expect(readdirSync(join(home!, 'iscp')).sort()).toEqual(['probe-profile'])
    expect(readdirSync(join(home!, 'iscp', 'probe-profile'))).toEqual(['bundle.json'])
  }

  it('happy --version prints the version and exits without touching the runtime', () => {
    const result = runCli(['--version'])
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    expect(result.stdout).toContain(`happy version: ${packageJson.version}`)
    expectNoRuntimeSideEffects(result)
  }, 90_000)

  it('happy --help prints help and exits without touching the runtime', () => {
    const result = runCli(['--help'])
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    expect(result.stdout).toContain('happy')
    expect(result.stdout).toContain('Usage:')
    expectNoRuntimeSideEffects(result)
  }, 90_000)
})
