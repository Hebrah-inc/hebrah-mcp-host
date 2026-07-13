/** In-memory rate limits and promotion confirmation tokens (Phase 1). */

import { incrementRateCounter } from './rateLimitStore.js'

const WINDOW_MS = 60_000
const WINDOW_SEC = 60
const MAX_CALLS_PER_WINDOW = 120
const MAX_PROMOTION_APPROVES_PER_DAY = 10
const CONFIRM_TTL_MS = 5 * 60_000

export type ConfirmationAction =
  | 'approve_promotion'
  | 'remove_connection'
  | 'set_connection_webhook_url'

type PendingConfirmation = {
  action: ConfirmationAction
  targetId: string
  expiresAt: number
}

type Bucket = { count: number, windowStart: number }

const callBuckets = new Map<string, Bucket>()
const approveBuckets = new Map<string, { count: number, dayStart: number }>()
const pendingConfirmations = new Map<string, PendingConfirmation>()

function dayKey(orgId: string) {
  const d = new Date()
  return `${orgId}:${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}`
}

export async function checkRateLimit(orgId: string, toolName: string): Promise<void> {
  const key = `${orgId}:${toolName}`
  await incrementRateCounter(key, MAX_CALLS_PER_WINDOW, WINDOW_SEC, () => {
    const now = Date.now()
    const bucket = callBuckets.get(key) ?? { count: 0, windowStart: now }
    if (now - bucket.windowStart > WINDOW_MS) {
      bucket.count = 0
      bucket.windowStart = now
    }
    bucket.count += 1
    callBuckets.set(key, bucket)
    if (bucket.count > MAX_CALLS_PER_WINDOW) {
      throw new Error(`Rate limit exceeded for ${toolName}. Try again in a minute.`)
    }
  })
}

export async function checkPromotionApproveLimit(orgId: string): Promise<void> {
  const key = dayKey(orgId)
  await incrementRateCounter(`promo-approve:${key}`, MAX_PROMOTION_APPROVES_PER_DAY, 86_400, () => {
    const now = Date.now()
    const bucket = approveBuckets.get(key) ?? { count: 0, dayStart: now }
    if (now - bucket.dayStart > 86_400_000) {
      bucket.count = 0
      bucket.dayStart = now
    }
    bucket.count += 1
    approveBuckets.set(key, bucket)
    if (bucket.count > MAX_PROMOTION_APPROVES_PER_DAY) {
      throw new Error('Promotion approve limit reached for today.')
    }
  })
}

export function issueConfirmationToken(
  action: ConfirmationAction,
  targetId: string
): string {
  const token = `confirm_${crypto.randomUUID().replace(/-/g, '')}`
  pendingConfirmations.set(token, {
    action,
    targetId,
    expiresAt: Date.now() + CONFIRM_TTL_MS
  })
  return token
}

export function consumeConfirmationToken(
  token: string,
  action: ConfirmationAction,
  targetId: string
): void {
  const entry = pendingConfirmations.get(token)
  if (!entry || entry.expiresAt < Date.now()) {
    throw new Error('Invalid or expired confirmation token. Call confirm_action first.')
  }
  if (entry.action !== action || entry.targetId !== targetId) {
    throw new Error('Confirmation token does not match this action.')
  }
  pendingConfirmations.delete(token)
}
