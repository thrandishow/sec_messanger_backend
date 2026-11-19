import { createConnection, type Socket } from 'node:net';
import { z } from 'zod';
import type { Config } from './config.js';
import { nicknameSchema, channelSchema, type ClientCommand, type ServerEvent } from './protocol.js';
import type { SavedMessage } from './store.js';

export type BrokerEvent = Exclude<ServerEvent, { type: 'error' }>
  | { type: 'error'; code: string; message: string; requestId?: string } | { type: 'accepted'; requestId: string; target: string };
const target = z.union([nicknameSchema, channelSchema]);
const eventSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('ready'), nickname: nicknameSchema }),
  z.object({ type: z.literal('accepted'), requestId: z.string().uuid(), target }),
  z.object({ type: z.literal('message'), id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    from: nicknameSchema, target, text: z.string().min(1).refine(s => Buffer.byteLength(s) <= 350), time: z.iso.datetime(),
    attachment: z.object({ id: z.string().uuid(), name: z.string().min(1).max(180), size: z.number().int().positive().max(10 * 1024 * 1024) }).optional() }),
  z.object({ type: z.literal('join'), nickname: nicknameSchema, channel: channelSchema }),
  z.object({ type: z.literal('part'), nickname: nicknameSchema, channel: channelSchema }),
  z.object({ type: z.literal('quit'), nickname: nicknameSchema }),
  z.object({ type: z.literal('names'), channel: channelSchema,
    members: z.array(z.object({ nickname: nicknameSchema, prefix: z.literal('') })).max(512) }),
  z.object({ type: z.literal('error'), code: z.string().max(64), message: z.string().max(256), requestId: z.string().max(64).optional() }),
  z.object({ type: z.literal('pong') }),
]);

export class BrokerBridge {
  private socket: Socket;
  private buffer = '';
  private ready = false;
  private closed = false;
  private deadline: NodeJS.Timeout;
  private heartbeat: NodeJS.Timeout;

  constructor(config: Config, nickname: string, private emit: (event: BrokerEvent) => void, private disconnected: () => void) {
    this.socket = createConnection({ host: config.brokerHost, port: config.brokerPort });
    this.socket.setEncoding('utf8'); this.socket.setNoDelay(true);
    this.socket.setTimeout(60_000, () => this.fail('BROKER_TIMEOUT'));
    this.deadline = setTimeout(() => this.fail('BROKER_TIMEOUT'), 5000);
    this.heartbeat = setInterval(() => { if (this.ready) this.write({ type: 'ping' }); }, 25_000);
    this.socket.on('connect', () => this.write({ type: 'hello', version: 1, nickname, token: config.brokerToken }));
    this.socket.on('data', (chunk: string) => this.receive(chunk));
    this.socket.on('error', () => this.fail('BROKER_UNAVAILABLE'));
    this.socket.on('close', () => { if (!this.closed) this.fail('BROKER_DISCONNECTED'); });
  }
  private write(command: unknown) {
    if (this.closed) return false;
    const line = JSON.stringify(command) + '\n';
    if (Buffer.byteLength(line) > 4096 || this.socket.writableLength > 64 * 1024) { this.fail('BROKER_OVERLOADED'); return false; }
    this.socket.write(line); return true;
  }
  command(command: Exclude<ClientCommand, { type: 'message' }>) {
    if (!this.ready || this.closed) { this.emit({ type: 'error', code: 'NOT_READY', message: 'Broker not ready' }); return; }
    this.write(command);
  }
  prepare(requestId: string, target: string) {
    if (!this.ready || this.closed) { this.emit({ type: 'error', code: 'NOT_READY', requestId, message: 'Broker not ready' }); return; }
    this.write({ type: 'prepare', requestId, target });
  }
  publish(requestId: string, message: SavedMessage) { return this.write({ type: 'publish', requestId, message }); }
  cancel(requestId: string) { this.write({ type: 'cancel', requestId }); }
  private receive(chunk: string) {
    this.buffer += chunk;
    let end: number;
    while ((end = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, end); this.buffer = this.buffer.slice(end + 1);
      if (Buffer.byteLength(line) > 256 * 1024) return this.fail('BROKER_PROTOCOL');
      let value: unknown;
      try { value = JSON.parse(line); } catch { return this.fail('BROKER_PROTOCOL'); }
      const parsed = eventSchema.safeParse(value);
      if (!parsed.success) return this.fail('BROKER_PROTOCOL');
      const event = parsed.data;
      if (event.type === 'ready') { this.ready = true; clearTimeout(this.deadline); }
      this.emit(event);
      if (event.type === 'error' && !this.ready) { this.close(); this.disconnected(); return; }
      if (this.closed) return;
    }
    if (Buffer.byteLength(this.buffer) > 256 * 1024) this.fail('BROKER_PROTOCOL');
  }
  private fail(code: string) {
    if (this.closed) return;
    this.close();
    this.emit({ type: 'error', code, message: 'Broker connection unavailable' });
    this.disconnected();
  }
  close() {
    if (this.closed) return;
    this.closed = true; clearTimeout(this.deadline); clearInterval(this.heartbeat); this.socket.destroy();
  }
}

/** Readiness verifies authentication and the routing task, not just an open TCP port. */
export function probeBroker(config: Config): Promise<boolean> {
  return new Promise(resolve => {
    const socket = createConnection({ host: config.brokerHost, port: config.brokerPort });
    let done = false; let buffer = '';
    const deadline = setTimeout(() => finish(false), 1500);
    const finish = (ok: boolean) => {
      if (done) return; done = true; clearTimeout(deadline); socket.destroy(); resolve(ok);
    };
    socket.setEncoding('utf8');
    socket.once('connect', () => socket.write(JSON.stringify({ type: 'health', token: config.brokerToken }) + '\n'));
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      if (buffer.length > 1024) return finish(false);
      const end = buffer.indexOf('\n'); if (end < 0) return;
      try { const data = JSON.parse(buffer.slice(0, end)); finish(data.type === 'health' && data.version === 1); }
      catch { finish(false); }
    });
    socket.once('error', () => finish(false)); socket.once('close', () => finish(false));
  });
}
