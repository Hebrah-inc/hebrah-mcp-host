import { config } from './config.js'

export async function logMcpAudit(input: {
  orgId: string
  tokenId?: string
  sessionId?: string
  toolName: string
  connectionId?: string
  policyDecision: string
  outcome: string
}) {
  try {
    await fetch(`${config.dashboardUrl}/api/internal/mcp/audit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-hebrah-mcp-internal-secret': config.mcpInternalSecret
      },
      body: JSON.stringify(input)
    })
  } catch {
    // non-fatal
  }
}