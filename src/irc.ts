import { createConnection, type Socket } from 'node:net';
import type { Config } from './config.js';
import { parseIrcLine, type ClientCommand, type ServerEvent } from './protocol.js';

export class IrcBridge {
  private socket: Socket;
  private buffer = '';
  private ready = false;
  private closed = false;
  private registrationTimer: NodeJS.Timeout;
  private joined = new Set<string>();
  private members = new Map<string, { nickname: string; prefix: string }[]>();

  constructor(config: Config, private nickname: string,
    private emit: (event: ServerEvent) => void, private disconnected: () => void) {
    this.socket = createConnection({ host: config.ircHost, port: config.ircPort });
    this.socket.setEncoding('utf8');
    this.socket.setTimeout(180_000, () => this.fail('IRC_TIMEOUT', 'IRC connection timed out'));
    this.registrationTimer = setTimeout(() => this.fail('IRC_TIMEOUT', 'IRC registration timed out'), 10_000);
    this.socket.on('connect', () => {
      this.write(`PASS ${config.ircPassword}`);
      this.write('CAP REQ :echo-message server-time');
      this.write(`NICK ${nickname}`);
      this.write(`USER ${nickname} 0 * :${nickname}`);
    });
    this.socket.on('data', (chunk: string) => this.receive(chunk));
    this.socket.on('error', () => this.fail('IRC_UNAVAILABLE', 'IRC server is unavailable'));
    this.socket.on('close', () => {
      clearTimeout(this.registrationTimer);
      if (!this.closed) {
        this.closed = true;
        this.emit({ type: 'error', code: 'IRC_DISCONNECTED', message: 'IRC connection closed' });
        this.disconnected();
      }
    });
  }

  private write(line: string) {
    if (this.closed) return;
    if (/[\r\n\0]/.test(line) || Buffer.byteLength(line) > 510) return this.fail('IRC_PROTOCOL', 'Invalid IRC command');
    if (this.socket.writableLength > 64 * 1024) return this.fail('SLOW_CONNECTION', 'IRC queue limit reached');
    this.socket.write(`${line}\r\n`);
  }

  command(command: ClientCommand) {
    if (!this.ready || this.closed) {
      this.emit({ type: 'error', code: 'NOT_READY', message: 'Wait for the ready event' });
      return;
    }
    switch (command.type) {
      case 'join': this.write(`JOIN ${command.channel}`); break;
      case 'part': this.write(`PART ${command.channel}`); break;
      case 'names':
        if (!this.joined.has(command.channel)) {
          this.emit({ type: 'error', code: 'NOT_JOINED', message: 'Join the channel first' });
        } else this.write(`NAMES ${command.channel}`);
        break;
      case 'message': this.write(`PRIVMSG ${command.target} :${command.text}`); break;
      case 'ping': this.emit({ type: 'pong' }); break;
    }
  }

  private receive(chunk: string) {
    this.buffer += chunk;
    let end: number;
    while ((end = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, end).replace(/\r$/, '');
      this.buffer = this.buffer.slice(end + 1);
      if (Buffer.byteLength(line) > 8192) return this.fail('IRC_PROTOCOL', 'IRC line limit reached');
      this.handle(line);
      if (this.closed) return;
    }
    if (Buffer.byteLength(this.buffer) > 8192) this.fail('IRC_PROTOCOL', 'IRC buffer limit reached');
  }

  private handle(line: string) {
    const m = parseIrcLine(line);
    if (!m) return;
    const p = m.params;
    const nick = m.prefix?.split('!')[0] ?? '';
    switch (m.command) {
      case 'PING': this.write(`PONG :${p[0] ?? ''}`); break;
      case 'CAP':
        if (p[1] === 'ACK') this.write('CAP END');
        if (p[1] === 'NAK') this.fail('IRC_CAPABILITIES', 'Required IRC capabilities are unavailable');
        break;
      case '001':
        this.ready = true;
        clearTimeout(this.registrationTimer);
        this.emit({ type: 'ready', nickname: this.nickname });
        break;
      case 'PRIVMSG':
        if (p[0] && p[1] !== undefined) this.emit({ type: 'message', from: nick, target: p[0], text: p[1],
          time: m.tags.time ?? new Date().toISOString() });
        break;
      case 'JOIN':
        if (p[0]) {
          if (nick === this.nickname) this.joined.add(p[0]);
          this.emit({ type: 'join', nickname: nick, channel: p[0] });
        }
        break;
      case 'PART':
        if (p[0]) {
          if (nick === this.nickname) { this.joined.delete(p[0]); this.members.delete(p[0]); }
          this.emit({ type: 'part', nickname: nick, channel: p[0] });
        }
        break;
      case 'QUIT': this.emit({ type: 'quit', nickname: nick }); break;
      case '353': {
        const channel = p[2];
        if (!channel || !this.joined.has(channel)) break;
        const list = this.members.get(channel) ?? [];
        for (const entry of (p[3] ?? '').split(' ').filter(Boolean)) {
          const prefix = entry.match(/^[~&@%+]+/)?.[0] ?? '';
          list.push({ nickname: entry.slice(prefix.length), prefix });
        }
        if (list.length > 2000) return this.fail('IRC_PROTOCOL', 'Member limit reached');
        this.members.set(channel, list);
        break;
      }
      case '366':
        if (p[1] && this.joined.has(p[1])) {
          this.emit({ type: 'names', channel: p[1], members: this.members.get(p[1]) ?? [] });
          this.members.delete(p[1]);
        }
        break;
      case '332':
        if (p[1]) this.emit({ type: 'topic', channel: p[1], text: p[2] ?? '' });
        break;
      case '331':
        if (p[1]) this.emit({ type: 'topic', channel: p[1], text: '' });
        break;
      case 'ERROR': this.fail('IRC_DISCONNECTED', 'IRC server closed the connection'); break;
      default:
        if (/^[45]\d\d$/.test(m.command) && m.command !== '422') {
          const message = {
            '401': 'Recipient is offline or does not exist', '403': 'Channel does not exist',
            '404': 'Cannot send to this channel', '405': 'Too many channels',
            '433': 'Nickname is already connected', '442': 'You are not in this channel',
            '464': 'IRC gateway authentication failed',
          }[m.command] ?? 'IRC rejected the command';
          this.emit({ type: 'error', code: `IRC_${m.command}`, message });
          if (!this.ready) { this.close(); this.disconnected(); }
        }
    }
  }

  private fail(code: string, message: string) {
    if (this.closed) return;
    this.emit({ type: 'error', code, message });
    this.close();
    this.disconnected();
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.registrationTimer);
    this.socket.destroy();
  }
}

export function probeIrc(config: Config): Promise<boolean> {
  return new Promise(resolve => {
    const socket = createConnection({ host: config.ircHost, port: config.ircPort });
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(1500, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.once('close', () => finish(false));
  });
}
