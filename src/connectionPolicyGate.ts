/** MCP connection lifecycle ACL — mirrors hebrah-app server/utils/mcpAcl.ts */

export type McpAcl = {
  connectionCreation: boolean
  connectionPause: boolean
  connectionRemoval: boolean
}

export type McpConnectionAction = 'creation' | 'pause' | 'removal'

export const MCP_ACL_DEFAULTS: McpAcl = {
  connectionCreation: true,
  connectionPause: true,
  connectionRemoval: false
}

export function normalizeMcpAcl(acl?: Partial<McpAcl> | null): McpAcl {
  return {
    connectionCreation: acl?.connectionCreation ?? MCP_ACL_DEFAULTS.connectionCreation,
    connectionPause: acl?.connectionPause ?? MCP_ACL_DEFAULTS.connectionPause,
    connectionRemoval: acl?.connectionRemoval ?? MCP_ACL_DEFAULTS.connectionRemoval
  }
}

function isAllowed(acl: McpAcl, action: McpConnectionAction): boolean {
  switch (action) {
    case 'creation':
      return acl.connectionCreation
    case 'pause':
      return acl.connectionPause
    case 'removal':
      return acl.connectionRemoval
    default:
      return false
  }
}

export function mcpConnectionDenyMessage(action: McpConnectionAction): string {
  switch (action) {
    case 'creation':
      return 'MCP connection creation is disabled for this organization. Enable it in Settings → MCP → Agent permissions.'
    case 'pause':
      return 'MCP connection pause/resume is disabled for this organization. Enable it in Settings → MCP → Agent permissions.'
    case 'removal':
      return 'MCP connection removal is disabled for this organization. Enable it in Settings → MCP → Agent permissions.'
  }
}

export function assertMcpConnectionActionAllowed(acl: McpAcl, action: McpConnectionAction): void {
  if (!isAllowed(acl, action)) {
    throw new Error(mcpConnectionDenyMessage(action))
  }
}

const LIFECYCLE_TOOLS: Record<string, McpConnectionAction | null> = {
  create_connection: 'creation',
  pause_connection: 'pause',
  resume_connection: 'pause',
  remove_connection: 'removal'
}

export function isConnectionLifecycleToolVisible(toolName: string, acl: McpAcl): boolean {
  const action = LIFECYCLE_TOOLS[toolName]
  if (!action) {
    return true
  }
  return isAllowed(acl, action)
}

export function filterToolsForAcl<T extends { name: string }>(tools: T[], acl: McpAcl): T[] {
  return tools.filter(t => isConnectionLifecycleToolVisible(t.name, acl))
}
