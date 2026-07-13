/** Redis-backed counters with in-memory fallback for MCP guardrails. */

let redisClient: import('ioredis').default | null | undefined

async function getRedis() {
  if (redisClient !== undefined) return redisClient
  const url = process.env.REDIS_URL?.trim()
  if (!url) {
    redisClient = null
    return null
  }
  try {
    const mod = await import('ioredis')
    type RedisClient = import('ioredis').default
    const RedisCtor = mod.default as unknown as new (
      url: string,
      options?: { maxRetriesPerRequest?: number, lazyConnect?: boolean }
    ) => RedisClient
    const client = new RedisCtor(url, { maxRetriesPerRequest: 1, lazyConnect: true })
    await client.connect()
    redisClient = client
    return redisClient
  } catch {
    redisClient = null
    return null
  }
}

export async function incrementRateCounter(
  key: string,
  limit: number,
  windowSeconds: number,
  memoryFallback: () => void
): Promise<void> {
  const redis = await getRedis()
  if (!redis) {
    memoryFallback()
    return
  }

  const redisKey = `hebrah:rl:${key}`
  try {
    const count = await redis.incr(redisKey)
    if (count === 1) {
      await redis.expire(redisKey, Math.max(1, windowSeconds))
    }
    if (count > limit) {
      throw new Error(`Rate limit exceeded for ${key}. Try again later.`)
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Rate limit exceeded')) {
      throw error
    }
    memoryFallback()
  }
}
