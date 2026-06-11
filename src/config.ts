import { loadEnvFile } from './loadEnv.js'

loadEnvFile()

function requireSecret(name: string, minLength = 32): string {
  const secret = process.env[name]?.trim()
  if (!secret) {
    throw new Error(`${name} is required (≥${minLength} chars). Run: bash ../scripts/generate-local-secrets.sh`)
  }
  if (secret.length < minLength) {
    throw new Error(`${name} must be at least ${minLength} characters`)
  }
  return secret
}

export const config = {
  port: Number(process.env.PORT || 3021),
  dashboardUrl: (process.env.HEBRAH_DASHBOARD_URL || 'http://localhost:3000').replace(/\/$/, ''),
  hebrahApiUrl: (process.env.HEBRAH_API_URL || 'http://localhost:8000').replace(/\/$/, ''),
  sandboxApiKey: process.env.HEBRAH_SANDBOX_API_KEY || '',
  mcpInternalSecret: requireSecret('MCP_INTERNAL_SECRET')
}
