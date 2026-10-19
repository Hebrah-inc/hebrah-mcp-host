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
  | 'create_sandbox_api_key'
  | 'rotate_connection_webhook_secret'
  | 'revoke_sandbox_api_key'
  | 'set_connection_webhook_url'
  | 'connect_to_data_source'
  | 'revoke_data_source_connection'

type PendingConfirmation = {
  action: ConfirmationAction
  targetId: string
  orgId: string
  expiresAt: number
}

type Bucket = { count: number, windowStart: number }

const MAX_BUCKETS = 5_000
const MAX_APPROVE_BUCKETS = 2_000
const MAX_PENDING_CONFIRMATIONS = 2_000

const callBuckets = new Map<string, Bucket>()
const approveBuckets = new Map<string, { count: number, dayStart: number }>()
const pendingConfirmations = new Map<string, PendingConfirmation>()

function prunePendingConfirmations(now = Date.now()) {
  for (const [token, entry] of pendingConfirmations) {
    if (entry.expiresAt < now) {
      pendingConfirmations.delete(token)
    }
  }
  while (pendingConfirmations.size >= MAX_PENDING_CONFIRMATIONS) {
    const oldestKey = pendingConfirmations.keys().next().value
    if (!oldestKey) break
    pendingConfirmations.delete(oldestKey)
  }
}

function dayKey(orgId: string) {
  const d = new Date()
  return `${orgId}:${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}`
}

export async function checkRateLimit(orgId: string, toolName: string): Promise<void> {
  const key = `${orgId}:${toolName}`
  await incrementRateCounter(key, MAX_CALLS_PER_WINDOW, WINDOW_SEC, () => {
    const now = Date.now()
    if (callBuckets.size >= MAX_BUCKETS && !callBuckets.has(key)) {
      for (const [k, b] of callBuckets) {
        if (now - b.windowStart > WINDOW_MS) callBuckets.delete(k)
      }
      if (callBuckets.size >= MAX_BUCKETS) {
        const oldest = callBuckets.keys().next().value
        if (oldest) callBuckets.delete(oldest)
      }
    }
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
  }, toolName)
}

export async function checkPromotionApproveLimit(orgId: string): Promise<void> {
  const key = dayKey(orgId)
  await incrementRateCounter(`promo-approve:${key}`, MAX_PROMOTION_APPROVES_PER_DAY, 86_400, () => {
    const now = Date.now()
    if (approveBuckets.size >= MAX_APPROVE_BUCKETS && !approveBuckets.has(key)) {
      for (const [k, b] of approveBuckets) {
        if (now - b.dayStart > 86_400_000) approveBuckets.delete(k)
      }
      if (approveBuckets.size >= MAX_APPROVE_BUCKETS) {
        const oldest = approveBuckets.keys().next().value
        if (oldest) approveBuckets.delete(oldest)
      }
    }
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
  }, 'promotion approval')
}

export function issueConfirmationToken(
  action: ConfirmationAction,
  targetId: string,
  orgId = ''
): string {
  prunePendingConfirmations()
  const token = `confirm_${crypto.randomUUID().replace(/-/g, '')}`
  pendingConfirmations.set(token, {
    action,
    targetId,
    orgId,
    expiresAt: Date.now() + CONFIRM_TTL_MS
  })
  return token
}

export function consumeConfirmationToken(
  token: string,
  action: ConfirmationAction,
  targetId: string,
  orgId = ''
): void {
  const entry = pendingConfirmations.get(token)
  if (!entry || entry.expiresAt < Date.now()) {
    if (entry) pendingConfirmations.delete(token)
    throw new Error('Invalid or expired confirmation token. Call confirm_action first.')
  }
  if (entry.orgId && orgId && entry.orgId !== orgId) {
    throw new Error('Confirmation token belongs to another organization.')
  }
  if (entry.action !== action || entry.targetId !== targetId) {
    throw new Error('Confirmation token does not match this action.')
  }
  pendingConfirmations.delete(token)
}
