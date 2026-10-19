export type DeliveryTarget = 'docker' | 'host' | 'auto'

const BLOCKED_METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  '100.100.100.200',
  '0.0.0.0',
  '[::]',
  '::'
])

const SAFE_HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|\[[0-9a-fA-F:]+\])$/

export function assertSafeHost(rawHost: string, fieldName = 'host'): string {
  const host = rawHost.trim().toLowerCase()
  if (!host || host.length > 253 || !SAFE_HOSTNAME_RE.test(host)) {
    throw new Error(`Invalid ${fieldName}: must be a valid hostname or IP literal without path or credentials`)
  }
  const bareIpv6 = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
  if (
    BLOCKED_METADATA_HOSTS.has(host) ||
    BLOCKED_METADATA_HOSTS.has(bareIpv6) ||
    host.startsWith('169.254.') ||
    bareIpv6.startsWith('fe80:') ||
    bareIpv6.startsWith('ff00:') ||
    host.endsWith('.internal')
  ) {
    throw new Error(`Invalid ${fieldName}: cloud metadata, link-local, and internal hosts are forbidden`)
  }
  return host
}

export function assertSafeWebhookOrCallbackUrl(
  rawUrl: string,
  fieldName = 'webhookUrl',
  options?: { disallowLoopback?: boolean }
): string {
  const trimmed = rawUrl.trim()
  if (!trimmed || trimmed.length > 2048) {
    throw new Error(`Invalid ${fieldName}: URL is required and must not exceed 2048 characters`)
  }
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    throw new Error(`Invalid ${fieldName}: must be a valid absolute http(s) URL`)
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Invalid ${fieldName}: protocol must be http: or https:`)
  }
  if (parsed.username || parsed.password) {
    throw new Error(`Invalid ${fieldName}: embedded credentials are not allowed in URL`)
  }
  const host = assertSafeHost(parsed.hostname, fieldName)
  if (options?.disallowLoopback && (isLoopbackHost(host) || host === '[::1]' || host === '::1')) {
    throw new Error(`Invalid ${fieldName}: loopback addresses are not allowed`)
  }
  return trimmed
}

export function webhookReceiverPath() {
  return '/api/webhooks/hebrah'
}

function isLoopbackHost(hostname: string) {
  return hostname === 'localhost' || hostname === '127.0.0.1'
}

function resolveDeliveryHost(hostname: string, deliveryTarget: DeliveryTarget) {
  if (deliveryTarget === 'docker') {
    return 'host.docker.internal'
  }
  if (deliveryTarget === 'host') {
    return hostname
  }
  return isLoopbackHost(hostname) ? 'host.docker.internal' : hostname
}

function buildReceiverUrl(host: string, port: string, protocol: string) {
  const scheme = protocol === 'https:' ? 'https' : 'http'
  const portSuffix = port && !((scheme === 'https' && port === '443') || (scheme === 'http' && port === '80'))
    ? `:${port}`
    : ''
  return `${scheme}://${host}${portSuffix}${webhookReceiverPath()}`
}

export type BuildLocalWebhookReceiverUrlInput = {
  localAppUrl?: string
  port?: number
  host?: string
  deliveryTarget?: DeliveryTarget
}

export function buildLocalWebhookReceiverUrl(input: BuildLocalWebhookReceiverUrlInput): string {
  const deliveryTarget = input.deliveryTarget ?? 'auto'

  if (input.localAppUrl?.trim()) {
    const safeUrl = assertSafeWebhookOrCallbackUrl(input.localAppUrl.trim(), 'localAppUrl')
    const base = new URL(safeUrl)
    const port = base.port || (base.protocol === 'https:' ? '443' : '80')
    const host = resolveDeliveryHost(base.hostname, deliveryTarget)
    return buildReceiverUrl(host, port, base.protocol)
  }

  if (input.port === undefined || Number.isNaN(input.port)) {
    throw new Error('localAppUrl or port is required to build a webhook receiver URL')
  }
  if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535) {
    throw new Error('port must be an integer between 1 and 65535')
  }

  const host = assertSafeHost(input.host?.trim() || 'localhost', 'host')
  const deliveryHost = resolveDeliveryHost(host, deliveryTarget)
  return buildReceiverUrl(deliveryHost, String(input.port), 'http:')
}

export function suggestedWebhookUrls(input: { localAppUrl?: string, port?: number, host?: string }) {
  return {
    host: buildLocalWebhookReceiverUrl({ ...input, deliveryTarget: 'host' }),
    docker: buildLocalWebhookReceiverUrl({ ...input, deliveryTarget: 'docker' })
  }
}

export function parseLocalAppUrlFromArgs(args: Record<string, unknown>) {
  const localAppUrl = String(args.localAppUrl ?? args.local_app_url ?? '').trim()
  if (localAppUrl) {
    assertSafeWebhookOrCallbackUrl(localAppUrl, 'localAppUrl')
    return { localAppUrl }
  }

  const portRaw = args.port
  if (portRaw !== undefined && portRaw !== null && portRaw !== '') {
    const port = Number(portRaw)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('port must be an integer between 1 and 65535')
    }
    const host = assertSafeHost(String(args.host ?? 'localhost').trim() || 'localhost', 'host')
    return { port, host }
  }

  return {}
}

export function resolveWebhookUrlFromSetArgs(args: Record<string, unknown>): string {
  const explicitUrl = String(args.webhookUrl ?? args.webhook_url ?? '').trim()
  if (explicitUrl) {
    return assertSafeWebhookOrCallbackUrl(explicitUrl, 'webhookUrl')
  }

  const deliveryTarget = String(args.deliveryTarget ?? args.delivery_target ?? 'auto') as DeliveryTarget
  if (!['docker', 'host', 'auto'].includes(deliveryTarget)) {
    throw new Error('deliveryTarget must be docker, host, or auto')
  }

  const urlInput = parseLocalAppUrlFromArgs(args)
  if (!('localAppUrl' in urlInput) && !('port' in urlInput)) {
    throw new Error('webhookUrl or localAppUrl or port is required for set_connection_webhook_url')
  }

  return buildLocalWebhookReceiverUrl({ ...urlInput, deliveryTarget })
}
