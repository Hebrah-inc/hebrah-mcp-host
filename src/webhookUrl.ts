export type DeliveryTarget = 'docker' | 'host' | 'auto'

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
    const base = new URL(input.localAppUrl.trim())
    const port = base.port || (base.protocol === 'https:' ? '443' : '80')
    const host = resolveDeliveryHost(base.hostname, deliveryTarget)
    return buildReceiverUrl(host, port, base.protocol)
  }

  if (input.port === undefined || Number.isNaN(input.port)) {
    throw new Error('localAppUrl or port is required to build a webhook receiver URL')
  }

  const host = input.host?.trim() || 'localhost'
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
    return { localAppUrl }
  }

  const portRaw = args.port
  if (portRaw !== undefined && portRaw !== null && portRaw !== '') {
    const port = Number(portRaw)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('port must be an integer between 1 and 65535')
    }
    const host = String(args.host ?? 'localhost').trim() || 'localhost'
    return { port, host }
  }

  return {}
}

export function resolveWebhookUrlFromSetArgs(args: Record<string, unknown>): string {
  const explicitUrl = String(args.webhookUrl ?? args.webhook_url ?? '').trim()
  if (explicitUrl) {
    return explicitUrl
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
