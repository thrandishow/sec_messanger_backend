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
