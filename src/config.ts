export const config = {
  port: Number(process.env.PORT || 3021),
  dashboardUrl: (process.env.WHILE_DASHBOARD_URL || 'http://localhost:3000').replace(/\/$/, ''),
  whileApiUrl: (process.env.WHILE_API_URL || 'http://localhost:8000').replace(/\/$/, ''),
  sandboxApiKey: process.env.WHILE_SANDBOX_API_KEY || '',
  mcpInternalSecret: process.env.MCP_INTERNAL_SECRET || 'dev-mcp-internal-secret'
}
