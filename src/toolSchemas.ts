const emptySchema = { type: 'object' as const, properties: {} }

/** Per-tool JSON Schema for tools/list — keep payloads small for MCP clients (e.g. Cursor). */
export function listToolInputSchema(toolName: string) {
  switch (toolName) {
    case 'create_connection':
      return {
        type: 'object' as const,
        required: ['name', 'ehrVendor'],
        properties: {
          name: { type: 'string' as const },
          ehrVendor: { type: 'string' as const, enum: ['Epic', 'Cerner', 'Athena'] as const },
          dataFormat: { type: 'string' as const },
          resourceTypes: { type: 'array' as const, items: { type: 'string' as const } }
        }
      }
    case 'create_account':
      return {
        type: 'object' as const,
        required: ['orgName', 'inviteEmail'],
        properties: {
          orgName: { type: 'string' as const, description: 'Organization name' },
          inviteEmail: { type: 'string' as const, format: 'email', description: 'Human team member who will claim the org and own payment' },
          agentName: { type: 'string' as const, description: 'Optional label for the agent creating the account' },
          ehrVendor: { type: 'string' as const, enum: ['Epic', 'Cerner', 'Athena', 'Other'] as const }
        }
      }
    case 'connect_to_data_source':
      return {
        type: 'object' as const,
        required: ['target', 'scopes', 'confirmationToken', 'humanIntentMessage'],
        properties: {
          target: { type: 'string' as const, description: 'Target from discover_data_sources' },
          scopes: { type: 'array' as const, items: { type: 'string' as const }, description: 'Exact required scopes from discovery' },
          tier: { type: 'string' as const, enum: ['container', 'vm'] as const },
          ttlSeconds: { type: 'number' as const, minimum: 60, maximum: 86400 },
          confirmationToken: { type: 'string' as const },
          humanIntentMessage: { type: 'string' as const }
        }
      }
    case 'query_data_source':
      return {
        type: 'object' as const,
        required: ['sql'],
        properties: {
          connectionId: { type: 'string' as const },
          sql: { type: 'string' as const, description: 'One read-only scoped query' }
        }
      }
    case 'get_data_source_audit':
    case 'get_connect_usage':
    case 'discover_data_sources':
      return emptySchema
    case 'revoke_data_source_connection':
      return {
        type: 'object' as const,
        required: ['confirmationToken', 'humanIntentMessage'],
        properties: {
          connectionId: { type: 'string' as const },
          confirmationToken: { type: 'string' as const },
          humanIntentMessage: { type: 'string' as const }
        }
      }
    case 'confirm_action':
      return {
        type: 'object' as const,
        required: ['action'],
        properties: {
          action: {
            type: 'string' as const,
            enum: [
              'approve_promotion',
              'remove_connection',
              'create_sandbox_api_key',
              'rotate_connection_webhook_secret',
            'revoke_sandbox_api_key',
              'set_connection_webhook_url',
              'revoke_data_source_connection'
            ] as const
          },
          connectionId: { type: 'string' as const },
          promotionId: { type: 'string' as const },
          keyId: { type: 'string' as const },
          humanIntentMessage: { type: 'string' as const }
        }
      }
    case 'approve_promotion':
    case 'remove_connection':
      return {
        type: 'object' as const,
        required: ['confirmationToken', 'humanIntentMessage'],
        properties: {
          connectionId: { type: 'string' as const },
          promotionId: { type: 'string' as const },
          confirmationToken: { type: 'string' as const },
          humanIntentMessage: { type: 'string' as const }
        }
      }
    case 'set_connection_webhook_url':
      return {
        type: 'object' as const,
        required: ['confirmationToken', 'humanIntentMessage'],
        properties: {
          connectionId: { type: 'string' as const },
          confirmationToken: { type: 'string' as const },
          humanIntentMessage: { type: 'string' as const },
          webhookUrl: { type: 'string' as const },
          inheritDefault: { type: 'boolean' as const },
          localAppUrl: { type: 'string' as const },
          port: { type: 'number' as const },
          host: { type: 'string' as const },
          deliveryTarget: {
            type: 'string' as const,
            enum: ['docker', 'host', 'auto'] as const
          }
        }
      }
    case 'get_connection_credentials':
      return {
        type: 'object' as const,
        properties: {
          connectionId: { type: 'string' as const },
          localAppUrl: { type: 'string' as const },
          port: { type: 'number' as const },
          host: { type: 'string' as const }
        }
      }
    case 'create_promotion':
      return {
        type: 'object' as const,
        required: ['toVersionId'],
        properties: {
          connectionId: { type: 'string' as const },
          toVersionId: { type: 'string' as const },
          title: { type: 'string' as const },
          description: { type: 'string' as const }
        }
      }
    case 'update_connection_mapping':
      return {
        type: 'object' as const,
        required: ['mappings'],
        properties: {
          connectionId: { type: 'string' as const },
          mappings: { type: 'array' as const, items: { type: 'object' as const } }
        }
      }
    case 'get_sdk_reference':
      return {
        type: 'object' as const,
        properties: {
          connectionId: { type: 'string' as const, description: 'Optional sandbox conn-sa-* for connection-scoped .env snippet' }
        }
      }
    case 'create_sandbox_api_key':
      return {
        type: 'object' as const,
        required: ['confirmationToken', 'humanIntentMessage'],
        properties: {
          connectionId: { type: 'string' as const },
          label: { type: 'string' as const },
          confirmationToken: { type: 'string' as const },
          humanIntentMessage: { type: 'string' as const }
        }
      }
    case 'list_sandbox_api_keys':
      return {
        type: 'object' as const,
        properties: { connectionId: { type: 'string' as const } }
      }
    case 'revoke_sandbox_api_key':
      return {
        type: 'object' as const,
        required: ['keyId', 'confirmationToken', 'humanIntentMessage'],
        properties: {
          connectionId: { type: 'string' as const },
          keyId: { type: 'string' as const },
          allowLast: { type: 'boolean' as const },
          confirmationToken: { type: 'string' as const },
          humanIntentMessage: { type: 'string' as const }
        }
      }
    case 'rotate_connection_webhook_secret':
      return {
        type: 'object' as const,
        required: ['confirmationToken', 'humanIntentMessage'],
        properties: {
          connectionId: { type: 'string' as const },
          confirmationToken: { type: 'string' as const },
          humanIntentMessage: { type: 'string' as const }
        }
      }
    case 'list_ptbxl_ecg_records':
      return {
        type: 'object' as const,
        properties: {
          superclass: {
            type: 'string' as const,
            enum: ['NORM', 'MI', 'STTC', 'CD', 'HYP'] as const
          },
          sex: { type: 'string' as const },
          fold: { type: 'number' as const },
          limit: { type: 'number' as const },
          offset: { type: 'number' as const }
        }
      }
    case 'get_ptbxl_ecg_record':
    case 'get_ptbxl_ecg_waveform_meta':
      return {
        type: 'object' as const,
        required: ['ecg_id'],
        properties: { ecg_id: { type: 'string' as const } }
      }
    case 'attach_ptbxl_ecg_exemplar':
      return {
        type: 'object' as const,
        required: ['patient_id', 'ecg_id'],
        properties: {
          connectionId: { type: 'string' as const },
          patient_id: { type: 'string' as const },
          ecg_id: { type: 'string' as const }
        }
      }
  }

  if (
    toolName.endsWith('_connection')
    || toolName.includes('connection_')
    || toolName.startsWith('get_connection')
    || toolName.includes('sandbox_api_key')
    || toolName.includes('webhook')
  ) {
    return {
      type: 'object' as const,
      properties: { connectionId: { type: 'string' as const } }
    }
  }

  return emptySchema
}
