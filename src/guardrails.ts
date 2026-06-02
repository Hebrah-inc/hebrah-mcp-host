/** In-memory rate limits and promotion confirmation tokens (Phase 1). */

const WINDOW_MS = 60_000
const MAX_CALLS_PER_WINDOW = 120
const MAX_PROMOTION_APPROVES_PER_DAY = 10
const CONFIRM_TTL_MS = 5 * 60_000

type Bucket = { count: number, windowStart: number }

const callBuckets = new Map<string, Bucket>()
const approveBuckets = new Map<string, { count: number, dayStart: number }>()
const pendingConfirmations = new Map<string, { promotionId: string, expiresAt: number }>()

function dayKey(orgId: string) {
  const d = new Date()
  return `${orgId}:${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}`
}

export function checkRateLimit(orgId: string, toolName: string): void {
  const key = `${orgId}:${toolName}`
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
}

export function checkPromotionApproveLimit(orgId: string): void {
  const key = dayKey(orgId)
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
}

export function issueConfirmationToken(promotionId: string): string {
  const token = `confirm_${crypto.randomUUID().replace(/-/g, '')}`
  pendingConfirmations.set(token, {
    promotionId,
    expiresAt: Date.now() + CONFIRM_TTL_MS
  })
  return token
}

export function consumeConfirmationToken(token: string, promotionId: string): void {
  const entry = pendingConfirmations.get(token)
  if (!entry || entry.expiresAt < Date.now()) {
    throw new Error('Invalid or expired confirmation token. Call confirm_action first.')
  }
  if (entry.promotionId !== promotionId) {
    throw new Error('Confirmation token does not match this promotion.')
  }
  pendingConfirmations.delete(token)
}
