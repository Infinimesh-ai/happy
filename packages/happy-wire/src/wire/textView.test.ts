import { describe, expect, it } from 'vitest';
import {
  PhoneTextViewBodySchema,
  RAW_SESSION_PROTOCOL_PERMISSION,
  projectPhoneTextView,
  wireViewForPermissions,
} from './textView';

/**
 * The exact production Codex session bodies from OPS 2026-08-18 §10.16
 * (session cmt16w4lrx513ye0ugtbkskwb, seq 1–8): the frozen regression sample.
 * The phone must end up with exactly one user bubble and one natural-language
 * agent bubble out of these eight events.
 */
const CODEX_SEQ_1_TO_8: unknown[] = [
  { content: { type: 'text', text: '你好' }, localKey: 'jingsi-37CD4599-F2FD-4A5A-B8C6-506A14DAB50E', role: 'user' },
  { role: 'session', content: { id: 'hzg7p120nbryhqjpmljgqtk3', time: 1787210360745, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'turn-start' } }, meta: { sentFrom: 'cli' } },
  { role: 'session', content: { id: 'p88navwp70szsuwxjfrvd77v', time: 1787210365354, role: 'agent', usage: { input_tokens: 12042, cache_creation_input_tokens: 0, cache_read_input_tokens: 1408, output_tokens: 66, context_window: 258400 }, ev: { t: 'service', text: '' } }, meta: { sentFrom: 'cli' } },
  { role: 'session', content: { id: 'e56y52ycuq2pj6tp2014j19s', time: 1787210368162, role: 'agent', usage: { input_tokens: 12679, cache_creation_input_tokens: 0, cache_read_input_tokens: 3456, output_tokens: 21, context_window: 258400 }, ev: { t: 'service', text: '' } }, meta: { sentFrom: 'cli' } },
  { role: 'session', content: { id: 'ori39x6jae2tofh4lglcwlio', time: 1787210371565, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'text', text: '你好！有什么我可以帮你处理的？' } }, meta: { sentFrom: 'cli' } },
  { role: 'session', content: { id: 'wt3ioyd9hd300nseqgo2l92v', time: 1787210371567, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'turn-end', status: 'completed' } }, meta: { sentFrom: 'cli' } },
  { role: 'agent', content: { id: 'f7dfeb45-1cd9-4a9a-b703-a40042078b23', type: 'event', data: { type: 'ready' } } },
  { role: 'session', content: { id: 'iszvgosmrb33ngsforko9zay', time: 1787210371603, role: 'agent', usage: { input_tokens: 458, cache_creation_input_tokens: 0, cache_read_input_tokens: 15744, output_tokens: 14, context_window: 258400 }, ev: { t: 'service', text: '' } }, meta: { sentFrom: 'cli' } },
];

function envelope(ev: Record<string, unknown>, extra: Record<string, unknown> = {}): unknown {
  return {
    role: 'session',
    content: {
      id: 'evtidevtidevtidevtidevti',
      time: 1787210360745,
      role: 'agent',
      turn: 'turnturnturnturnturnturn',
      ...extra,
      ev,
    },
  };
}

describe('projectPhoneTextView', () => {
  it('projects the production Codex seq 1–8 to exactly one user and one agent bubble', () => {
    const emitted = CODEX_SEQ_1_TO_8.map((body) => projectPhoneTextView(body)).filter(
      (projection) => projection.emit !== null,
    );
    expect(emitted).toHaveLength(2);
    expect(emitted[0].emit).toEqual({
      role: 'user',
      content: { type: 'text', text: '你好' },
      localKey: 'jingsi-37CD4599-F2FD-4A5A-B8C6-506A14DAB50E',
    });
    expect(emitted[1].emit).toEqual({
      role: 'agent',
      content: { type: 'text', text: '你好！有什么我可以帮你处理的？' },
    });
    for (const projection of emitted) {
      expect(PhoneTextViewBodySchema.safeParse(projection.emit).success).toBe(true);
    }
  });

  it('classifies every dropped Codex event without leaking the body', () => {
    const kinds = CODEX_SEQ_1_TO_8.map((body) => projectPhoneTextView(body)).map((p) => p.kind);
    expect(kinds).toEqual([
      'user-text',
      'session-turn-start',
      'session-service',
      'session-service',
      'session-text',
      'session-turn-end',
      'legacy-agent-event',
      'session-service',
    ]);
    for (const projection of CODEX_SEQ_1_TO_8.map((body) => projectPhoneTextView(body))) {
      if (projection.emit === null) {
        expect(projection.dropReason).not.toContain('你好');
      }
    }
  });

  it('emits agent text with the exact visible text and nothing else', () => {
    const projection = projectPhoneTextView(envelope({ t: 'text', text: 'plain reply' }));
    expect(projection).toEqual({
      kind: 'session-text',
      emit: { role: 'agent', content: { type: 'text', text: 'plain reply' } },
    });
  });

  it('projects phone approval lifecycle records without provider arguments or call ids', () => {
    const pending = projectPhoneTextView({
      role: 'happy-control',
      content: {
        type: 'approval',
        toolName: 'CodexBash',
        status: 'pending',
        arguments: { command: 'curl https://example.com' },
        callId: 'internal-call-id',
      },
    });
    expect(pending).toEqual({
      kind: 'phone-approval-pending',
      emit: {
        role: 'agent',
        content: {
          type: 'approval',
          toolName: 'CodexBash',
          status: 'pending',
          approveCommand: '/approve',
          denyCommand: '/deny',
        },
      },
    });
    expect(JSON.stringify(pending)).not.toContain('example.com');
    expect(JSON.stringify(pending)).not.toContain('internal-call-id');
    expect(PhoneTextViewBodySchema.safeParse(pending.emit).success).toBe(true);

    for (const status of ['approved', 'denied'] as const) {
      const completed = projectPhoneTextView({
        role: 'happy-control',
        content: { type: 'approval', toolName: 'CodexBash', status },
      });
      expect(completed).toEqual({
        kind: `phone-approval-${status}`,
        emit: {
          role: 'agent',
          content: { type: 'approval', toolName: 'CodexBash', status },
        },
      });
      expect(PhoneTextViewBodySchema.safeParse(completed.emit).success).toBe(true);
    }
  });

  it('rejects malformed approval cards at the phone-view schema boundary', () => {
    expect(PhoneTextViewBodySchema.safeParse({
      role: 'agent',
      content: { type: 'approval', toolName: 'Bash', status: 'pending' },
    }).success).toBe(false);
    expect(PhoneTextViewBodySchema.safeParse({
      role: 'agent',
      content: {
        type: 'approval',
        toolName: 'Bash',
        status: 'approved',
        approveCommand: '/approve',
        denyCommand: '/deny',
      },
    }).success).toBe(false);
  });

  it('drops thinking text', () => {
    const projection = projectPhoneTextView(envelope({ t: 'text', text: 'internal reasoning', thinking: true }));
    expect(projection.emit).toBeNull();
    expect(projection.kind).toBe('session-thinking');
  });

  it('drops subagent text', () => {
    const projection = projectPhoneTextView(
      envelope({ t: 'text', text: 'subagent chatter' }, { subagent: 'tz4a98xxat96iws9zmbrgj3a' }),
    );
    expect(projection.emit).toBeNull();
    expect(projection.kind).toBe('session-subagent-text');
  });

  it('drops empty agent text and empty user text', () => {
    expect(projectPhoneTextView(envelope({ t: 'text', text: '' })).emit).toBeNull();
    expect(projectPhoneTextView({ role: 'user', content: { type: 'text', text: '' } }).emit).toBeNull();
  });

  it('drops session-envelope user text (the ingested send is authoritative)', () => {
    const projection = projectPhoneTextView({
      role: 'session',
      content: { id: 'evtidevtidevtidevtidevti', time: 1, role: 'user', ev: { t: 'text', text: 'echo' } },
    });
    expect(projection.emit).toBeNull();
    expect(projection.kind).toBe('session-user-text');
  });

  it('drops tool, file, start/stop and non-empty service events', () => {
    const cases: Array<[unknown, string]> = [
      [envelope({ t: 'tool-call-start', call: 'c1', name: 'Bash', title: 'run', description: 'runs', args: {} }), 'session-tool-call-start'],
      [envelope({ t: 'tool-call-end', call: 'c1' }), 'session-tool-call-end'],
      [envelope({ t: 'file', ref: 'r', name: 'a.png', size: 10 }), 'session-file'],
      [envelope({ t: 'start', title: 'hello' }), 'session-start'],
      [envelope({ t: 'stop' }), 'session-stop'],
      [envelope({ t: 'service', text: 'rate limited, retrying' }), 'session-service'],
    ];
    for (const [body, kind] of cases) {
      const projection = projectPhoneTextView(body);
      expect(projection.emit).toBeNull();
      expect(projection.kind).toBe(kind);
    }
  });

  it('drops legacy agent output/codex/acp messages with a per-type kind', () => {
    for (const type of ['output', 'codex', 'acp']) {
      const projection = projectPhoneTextView({ role: 'agent', content: { type, data: { anything: true } } });
      expect(projection.emit).toBeNull();
      expect(projection.kind).toBe(`legacy-agent-${type}`);
    }
  });

  it('fails closed on unknown bodies', () => {
    for (const body of [null, 42, 'text', {}, { role: 'session', content: { nonsense: true } }, { role: 'weird' }]) {
      const projection = projectPhoneTextView(body);
      expect(projection.emit).toBeNull();
      expect(projection.kind).toBe('unknown');
    }
  });
});

describe('wireViewForPermissions', () => {
  it('serves the text view for the production text-only grant', () => {
    expect(wireViewForPermissions(['text'])).toBe('text');
  });

  it('serves the text view for empty or unknown permission sets (fail-closed)', () => {
    expect(wireViewForPermissions([])).toBe('text');
    expect(wireViewForPermissions(['tool', 'file'])).toBe('text');
  });

  it('serves raw only for the explicit raw-session permission', () => {
    expect(wireViewForPermissions([RAW_SESSION_PROTOCOL_PERMISSION])).toBe('raw');
    expect(wireViewForPermissions(['text', RAW_SESSION_PROTOCOL_PERMISSION])).toBe('raw');
  });
});
