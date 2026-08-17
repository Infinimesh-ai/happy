import { afterEach, describe, expect, it, vi } from 'vitest'

import { startIscpSessionRpcServer, USER_MESSAGE_METHOD, type IscpSessionRpcServer } from './sessionRpcServer'
import { daemonPost } from '@/daemon/controlClient'

vi.mock('@/daemon/controlClient', () => ({
  daemonPost: vi.fn(async () => ({ status: 'ok' })),
}))

const daemonPostMock = vi.mocked(daemonPost)

const waitFor = async (predicate: () => boolean, timeoutMs = 2000): Promise<void> => {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('condition not met in time')
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}

describe('startIscpSessionRpcServer', () => {
  let server: IscpSessionRpcServer | null = null
  afterEach(async () => {
    await server?.stop()
    server = null
    daemonPostMock.mockReset()
    daemonPostMock.mockImplementation(async () => ({ status: 'ok' }))
  })

  it('bridges user messages and RPC calls over localhost', async () => {
    const onUserMessage = vi.fn()
    const callHandler = vi.fn(async () => ({ answered: true }))
    server = await startIscpSessionRpcServer({
      profileId: 'p1',
      sessionId: 's1',
      onUserMessage,
      callHandler,
      retryIntervalMs: 10,
      heartbeatIntervalMs: 10_000,
    })

    const userMessage = await fetch(`http://127.0.0.1:${server.port}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: USER_MESSAGE_METHOD, params: { t: 'hi' } }),
    })
    expect(await userMessage.json()).toEqual({ ok: true, result: null })
    expect(onUserMessage).toHaveBeenCalledWith({ t: 'hi' })

    const rpc = await fetch(`http://127.0.0.1:${server.port}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'abort', params: {} }),
    })
    expect(await rpc.json()).toEqual({ ok: true, result: { answered: true } })
    expect(callHandler).toHaveBeenCalledWith('abort', {})
  })

  it('keeps re-registering on a heartbeat so a daemon restart re-learns the port', async () => {
    server = await startIscpSessionRpcServer({
      profileId: 'p1',
      sessionId: 's1',
      onUserMessage: () => {},
      callHandler: async () => null,
      retryIntervalMs: 5,
      heartbeatIntervalMs: 10,
    })
    // Registration is not one-shot: successful registrations keep repeating.
    await waitFor(() => daemonPostMock.mock.calls.length >= 3)
    for (const call of daemonPostMock.mock.calls) {
      expect(call[0]).toBe('/iscp/session-rpc')
      expect(call[1]).toMatchObject({ profileId: 'p1', sessionId: 's1', port: server!.port })
    }
  })

  it('retries through daemon outages and stops cleanly', async () => {
    let failures = 0
    daemonPostMock.mockImplementation(async () => {
      if (failures < 3) {
        failures += 1
        return { error: 'daemon not running' }
      }
      return { status: 'ok' }
    })
    server = await startIscpSessionRpcServer({
      profileId: 'p1',
      sessionId: 's1',
      onUserMessage: () => {},
      callHandler: async () => null,
      retryIntervalMs: 5,
      heartbeatIntervalMs: 10,
    })
    await waitFor(() => daemonPostMock.mock.calls.length >= 5)
    expect(failures).toBe(3)

    await server.stop()
    const callsAtStop = daemonPostMock.mock.calls.length
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(daemonPostMock.mock.calls.length).toBe(callsAtStop)
    server = null
  })
})
