import {
  MCP_TO_SDK,
  NODE_SDK_NPM_URL,
  NODE_SDK_PACKAGE,
  NODE_SDK_REFERENCE_MARKDOWN,
  NODE_SDK_VERSION
} from './generated/nodeSdkReference.js'

export type SdkReferenceResult = {
  package: string
  version: string
  npmUrl: string
  markdown: string
  mcpToSdk: Record<string, string>
  connectionEnv?: {
    connectionId: string
    snippet: string
  }
}

function connectionEnvSnippet(connectionId: string): string {
  return [
    '# Connection-scoped .env for local demo apps',
    '',
    'HEBRAH_API_KEY=hb_test_...          # from onboarding Step 2 or dashboard Credentials',
    `HEBRAH_CONNECTION_ID=${connectionId}`,
    'HEBRAH_API_BASE_URL=http://localhost:8000',
    'HEBRAH_WEBHOOK_SECRET=hbsec_...     # from onboarding Step 2 — write to demo .env',
    '',
    '# After building your local receiver, wire the connection webhook URL via MCP:',
    '# 1. get_connection_credentials(localAppUrl=http://localhost:YOUR_PORT)',
    '# 2. confirm_action(action=set_connection_webhook_url, connectionId)',
    '# 3. set_connection_webhook_url(port=YOUR_PORT, deliveryTarget=docker)',
    ''
  ].join('\n')
}

export function buildSdkReference(connectionId?: string): SdkReferenceResult {
  const result: SdkReferenceResult = {
    package: NODE_SDK_PACKAGE,
    version: NODE_SDK_VERSION,
    npmUrl: NODE_SDK_NPM_URL,
    markdown: NODE_SDK_REFERENCE_MARKDOWN,
    mcpToSdk: { ...MCP_TO_SDK }
  }

  if (connectionId) {
    result.connectionEnv = {
      connectionId,
      snippet: connectionEnvSnippet(connectionId)
    }
    result.markdown = `${NODE_SDK_REFERENCE_MARKDOWN}\n## Connection-scoped environment\n\n\`\`\`bash\n${connectionEnvSnippet(connectionId)}\`\`\`\n`
  }

  return result
}

export { NODE_SDK_REFERENCE_MARKDOWN, NODE_SDK_PACKAGE, NODE_SDK_VERSION }
