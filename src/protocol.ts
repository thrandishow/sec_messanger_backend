import { z } from 'zod';

export const nicknameSchema = z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]{2,23}$/);
export const channelSchema = z.string().regex(/^#[a-z0-9][a-z0-9_-]{0,47}$/);
const textSchema = z.string().min(1).refine(s => !/[\x00-\x1f\x7f]/.test(s), 'Control characters are forbidden');
export const clientCommandSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('join'), channel: channelSchema }).strict(),
  z.object({ type: z.literal('part'), channel: channelSchema }).strict(),
  z.object({ type: z.literal('message'), target: z.union([channelSchema, nicknameSchema]),
    text: textSchema.refine(s => Buffer.byteLength(s, 'utf8') <= 350, 'Maximum 350 UTF-8 bytes'), attachmentId: z.string().uuid().optional() }).strict(),
  z.object({ type: z.literal('names'), channel: channelSchema }).strict(),
  z.object({ type: z.literal('ping') }).strict(),
]);
export type ClientCommand = z.infer<typeof clientCommandSchema>;

export type ServerEvent =
  | { type: 'ready'; nickname: string }
  | { type: 'message'; from: string; target: string; text: string; time: string; id?: number; attachment?: { id: string; name: string; size: number } }
  | { type: 'join' | 'part'; nickname: string; channel: string }
  | { type: 'quit'; nickname: string }
  | { type: 'names'; channel: string; members: { nickname: string; prefix: string }[] }
  | { type: 'topic'; channel: string; text: string }
  | { type: 'error'; code: string; message: string }
  | { type: 'pong' };

export type IrcMessage = { tags: Record<string, string>; prefix?: string; command: string; params: string[] };

export function parseIrcLine(line: string): IrcMessage | null {
  const tags: Record<string, string> = Object.create(null);
  let rest = line;
  if (rest.startsWith('@')) {
    const end = rest.indexOf(' ');
    if (end === -1) return null;
    for (const tag of rest.slice(1, end).split(';')) {
      const equals = tag.indexOf('=');
      const key = equals === -1 ? tag : tag.slice(0, equals);
      const value = equals === -1 ? '' : tag.slice(equals + 1);
      tags[key] = value.replace(/\\(.)/g, (_, c: string) => ({ ':': ';', s: ' ', r: '\r', n: '\n', '\\': '\\' }[c] ?? c));
    }
    rest = rest.slice(end + 1).trimStart();
  }
  let prefix: string | undefined;
  if (rest.startsWith(':')) {
    const end = rest.indexOf(' ');
    if (end === -1) return null;
    prefix = rest.slice(1, end);
    rest = rest.slice(end + 1).trimStart();
  }
  const parts: string[] = [];
  while (rest) {
    if (rest.startsWith(':')) { parts.push(rest.slice(1)); break; }
    const end = rest.indexOf(' ');
    if (end === -1) { parts.push(rest); break; }
    parts.push(rest.slice(0, end));
    rest = rest.slice(end + 1).trimStart();
  }
  const command = parts.shift();
  return command ? { tags, prefix, command: command.toUpperCase(), params: parts } : null;
}
