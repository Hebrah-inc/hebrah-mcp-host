export const config = {
  port: Number(process.env.PORT || 3021),
  dashboardUrl: (process.env.HEBRAH_DASHBOARD_URL || 'http://localhost:3000').replace(/\/$/, ''),
  hebrahApiUrl: (process.env.HEBRAH_API_URL || 'http://localhost:8000').replace(/\/$/, ''),
  sandboxApiKey: process.env.HEBRAH_SANDBOX_API_KEY || '',
  mcpInternalSecret: process.env.MCP_INTERNAL_SECRET || 'REDACTED_DEV_SECRET'
}