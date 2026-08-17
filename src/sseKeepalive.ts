/** Cloudflare edge closes idle SSE streams after ~5 minutes; keepalive avoids drops. */
export const SSE_KEEPALIVE_INTERVAL_MS = 25_000
export const SSE_KEEPALIVE_FRAME = ': keepalive\n\n'

/** Wrap an SSE Response body with periodic comment frames for proxy idle watchdogs. */
export function wrapSseResponseWithKeepalive(response: Response): Response {
  const contentType = response.headers.get('content-type') ?? ''
  if (!contentType.includes('text/event-stream') || !response.body) {
    return response
  }

  const encoder = new TextEncoder()
  let keepaliveTimer: ReturnType<typeof setInterval> | undefined
  const reader = response.body.getReader()

  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      keepaliveTimer = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(SSE_KEEPALIVE_FRAME))
        } catch {
          if (keepaliveTimer) clearInterval(keepaliveTimer)
        }
      }, SSE_KEEPALIVE_INTERVAL_MS)

      const pump = async () => {
        try {
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            if (value) controller.enqueue(value)
          }
        } finally {
          if (keepaliveTimer) clearInterval(keepaliveTimer)
          try {
            controller.close()
          } catch {
            // already closed
          }
        }
      }

      pump().catch(() => {
        if (keepaliveTimer) clearInterval(keepaliveTimer)
        try {
          controller.close()
        } catch {
          // already closed
        }
      })
    },
    cancel() {
      if (keepaliveTimer) clearInterval(keepaliveTimer)
      reader.cancel().catch(() => undefined)
    }
  })

  const headers = new Headers(response.headers)
  headers.set('X-Accel-Buffering', 'no')

  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers
  })
}
