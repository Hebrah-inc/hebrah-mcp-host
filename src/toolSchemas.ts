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
    case 'list_dicom_imaging_records':
      return {
        type: 'object' as const,
        properties: {
          modality: {
            type: 'string' as const,
            enum: ['DX', 'CT', 'MR', 'XA', 'US', 'MG', 'PT'] as const,
            description: 'Filter by DICOM modality (DX, CT, MR, XA, US, MG, PT)'
          },
          archetype_id: {
            type: 'string' as const,
            description: 'Filter by clinical archetype ID (e.g. cardiology_center, neurology_stroke, hospital_system)'
          },
          limit: { type: 'number' as const },
          offset: { type: 'number' as const }
        }
      }
    case 'get_dicom_imaging_record':
      return {
        type: 'object' as const,
        required: ['exemplar_id'],
        properties: {
          exemplar_id: { type: 'string' as const, description: 'Exemplar ID (e.g. dicom-ct-001, dicom-mr-001, dicom-xa-001)' }
        }
      }
    case 'attach_dicom_imaging_exemplar':
      return {
        type: 'object' as const,
        required: ['environment_id', 'patient_id'],
        properties: {
          environment_id: { type: 'string' as const, description: 'Target isolated environment ID' },
          patient_id: { type: 'string' as const, description: 'Target patient ID in the environment' },
          exemplar_id: { type: 'string' as const, description: 'Optional open-data DICOM exemplar ID (e.g. dicom-ct-001)' },
          modality: { type: 'string' as const, description: 'Optional DICOM modality (CT, MR, DX, XA, US, MG, PT)' }
        }
      }
    case 'env_list':
      return {
        type: 'object' as const,
        properties: {
          include_destroyed: { type: 'boolean' as const, description: 'Whether to include destroyed environments (default: false)' }
        }
      }
    case 'env_create':
      return {
        type: 'object' as const,
        required: ['name'],
        properties: {
          name: { type: 'string' as const, description: 'Clinic environment name' },
          clinic_type: {
            type: 'string' as const,
            enum: CLINICAL_ARCHETYPE_VALUES,
            description: 'Clinical archetype (16 archetypes supported, e.g. ambulatory_clinic, hospital_system, cardiology_center, emergency_trauma, icu_critical_care, oncology_infusion, orthopedic_surgery, labor_delivery_obgyn, pediatrics_neonatal, behavioral_health, neurology_stroke, nephrology_dialysis, gastroenterology_endoscopy, pulmonology_sleep, rehabilitation_snf, urgent_care_network)'
          },
          patient_cohort: {
            type: 'string' as const,
            enum: ['general', 'geriatric', 'pediatric', 'cardiac', 'mixed'] as const,
            description: 'Synthetic patient cohort'
          },
          departments: { type: 'array' as const, items: { type: 'string' as const }, description: 'Hospital departments (emergency, icu, cardiology, oncology, obstetrics, pediatrics, behavioral, ambulatory)' },
          diagnosis_pathways: { type: 'array' as const, items: { type: 'string' as const }, description: 'Specific clinical archetype IDs' },
          treatment_modalities: { type: 'array' as const, items: { type: 'string' as const }, description: 'Treatment modalities' },
          acuity_levels: { type: 'array' as const, items: { type: 'string' as const }, description: 'Acuity levels (routine, urgent, emergent, critical)' },
          capability_packs: { type: 'array' as const, items: { type: 'string' as const }, description: 'Base clinical capability packs (vocab_clinical, fhir_bulk_export, imaging_dicom, device_ieee11073, hie_ccda_xds, emerging_sdoh_genomics)' },
          addons: { type: 'array' as const, items: { type: 'string' as const }, description: 'Database pack modules (postgres, sqlite, vectordb, neo4j)' },
          patient_count: { type: 'number' as const, description: 'Initial patient pool size (10-1000)' },
          bed_count: { type: 'number' as const, description: 'Inpatient bed capacity (0-200)' }
        }
      }
    case 'env_consult_architect':
    case 'hebrah_consult_architect':
      return {
        type: 'object' as const,
        required: ['message'],
        properties: {
          message: { type: 'string' as const, description: 'Natural language description of your clinical integration or AI agent testing needs' },
          session_id: { type: 'string' as const, description: 'Optional architect session ID to continue a multi-turn blueprint refinement' },
          auto_provision: { type: 'boolean' as const, description: 'If true, automatically provisions the synthesized EnvironmentBlueprint when ready' }
        }
      }
    case 'env_admit_patients':
      return {
        type: 'object' as const,
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' },
          count: { type: 'number' as const, description: 'Number of new synthetic patients to admit (1-100, default: 10)' },
          departments: { type: 'array' as const, items: { type: 'string' as const }, description: 'Hospital departments' },
          diagnosis_pathways: { type: 'array' as const, items: { type: 'string' as const }, description: 'Specific clinical archetype IDs' },
          treatment_modalities: { type: 'array' as const, items: { type: 'string' as const }, description: 'Treatment modalities' },
          acuity_levels: { type: 'array' as const, items: { type: 'string' as const }, description: 'Acuity levels (routine, urgent, emergent, critical)' }
        }
      }
    case 'env_connect':
      return {
        type: 'object' as const,
        required: ['environment_id'],
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID to connect this agent session to' },
          agent_name: { type: 'string' as const, description: 'Optional display name for this agent in the Connected Agents table' }
        }
      }
    case 'env_get':
      return {
        type: 'object' as const,
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' }
        }
      }
    case 'env_list_tables':
      return {
        type: 'object' as const,
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' }
        }
      }
    case 'env_query_db':
      return {
        type: 'object' as const,
        required: ['sql'],
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' },
          sql: { type: 'string' as const, description: 'Read-only SQL query to execute against environment database module' },
          addon: { type: 'string' as const, enum: ['postgres', 'sqlite'] as const, description: 'Database module (default: postgres)' }
        }
      }
    case 'env_record_outcome':
      return {
        type: 'object' as const,
        required: ['outcome_type', 'summary'],
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' },
          outcome_type: { type: 'string' as const, description: 'Clinical outcome category (e.g. sepsis_risk_alert, care_gap_closed, triage_recommendation)' },
          summary: { type: 'string' as const, description: 'Human-readable summary of the clinical finding or outcome (scanned by DLP filter)' },
          patient_id: { type: 'string' as const, description: 'Target synthetic patient ID (e.g. pat-4e39-001)' },
          score: { type: 'number' as const, description: 'Optional numeric risk or confidence score (0-100 or 0.0-1.0)' },
          source_agent: { type: 'string' as const, description: 'Optional agent identifier attribution' },
          payload: { type: 'object' as const, description: 'Optional structured JSON metadata for the outcome' }
        }
      }
    case 'env_trigger_scenario':
      return {
        type: 'object' as const,
        required: ['scenario'],
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' },
          scenario: { type: 'string' as const, enum: ['er_arrival', 'lab_critical', 'discharge', 'code_blue', 'vitals_spike', 'icu_sepsis_deterioration', 'ventilator_desaturation_alarm'] as const, description: 'Clinical scenario name' },
          patient_id: { type: 'string' as const, description: 'Optional target patient ID' },
          notes: { type: 'string' as const, description: 'Optional clinical notes' }
        }
      }
    case 'env_list_patients':
      return {
        type: 'object' as const,
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' },
          department: { type: 'string' as const, description: 'Filter by hospital department (emergency, icu, cardiology, oncology, obstetrics, pediatrics, behavioral, ambulatory)' },
          diagnosis: { type: 'string' as const, description: 'Filter by diagnosis pathway, ICD-10 code, or SNOMED CT code' },
          treatment_modality: { type: 'string' as const, description: 'Filter by treatment modality' },
          acuity_level: { type: 'string' as const, description: 'Filter by acuity level (routine, urgent, emergent, critical)' },
          limit: { type: 'number' as const, description: 'Maximum number of patients to return (1-200, default: 50)' }
        }
      }
    case 'env_get_patient_chart':
      return {
        type: 'object' as const,
        required: ['patient_id'],
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' },
          patient_id: { type: 'string' as const, description: 'Patient ID (e.g. pat_001)' }
        }
      }
    case 'env_get_logs':
      return {
        type: 'object' as const,
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' },
          limit: { type: 'number' as const, description: 'Maximum number of audit log entries to return (1-200, default: 50)' },
          event_type: { type: 'string' as const, description: 'Optional filter by event_type (e.g. db_query, db_write, scenario_triggered, agent.connected)' }
        }
      }
    case 'env_pause':
    case 'env_resume':
      return {
        type: 'object' as const,
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' }
        }
      }
    case 'env_consult_studio':
      return {
        type: 'object' as const,
        required: ['message'],
        properties: {
          environment_id: { type: 'string' as const, description: 'Environment ID (defaults to active session environment)' },
          message: { type: 'string' as const, description: 'Clinical data, open-data evidence, or SQL/FHIR/DICOM/CDS exploration prompt for the Per-Environment AI Studio (locked to this environment; external skill/tool installation requests are blocked)' },
          session_id: { type: 'string' as const, description: 'Optional Studio session ID to continue a multi-turn exploration thread' }
        }
      }
    case 'hebrah_concierge_chat':
      return {
        type: 'object' as const,
        required: ['message'],
        properties: {
          message: { type: 'string' as const, description: 'Natural-language message for the Hosted Personal Concierge (Stage 1 onboarding, blueprint design, account/environment creation, and Hebrah Q&A) or Personal Account & Environment Studio Agent (Stage 2 clinical exploration, scenarios, outcomes, SDK snippets, and account management)' },
          session_id: { type: 'string' as const, description: 'Optional Concierge or Studio session ID to continue a conversation' },
          session_token: { type: 'string' as const, description: 'Optional pre-auth onboarding session token (hb_onb_...)' },
          environment_id: { type: 'string' as const, description: 'Optional Environment ID to focus Stage 2 Studio on (defaults to active session environment)' },
          org_name: { type: 'string' as const, description: 'Optional organization name when creating a new headless agent account during onboarding' },
          invite_email: { type: 'string' as const, description: 'Optional human teammate/owner email to send a claim/adoption invitation to' },
          auto_provision: { type: 'boolean' as const, description: 'Set true to immediately create the account and provision the recommended clinical environment' }
        }
      }
    case 'env_invite_human':
      return {
        type: 'object' as const,
        required: ['invite_email'],
        properties: {
          invite_email: { type: 'string' as const, description: 'Email address of the human teammate or organization owner to invite' },
          org_name: { type: 'string' as const, description: 'Optional organization display name' }
        }
      }
    case 'env_search_clinical_evidence':
      return {
        type: 'object' as const,
        properties: {
          environment_id: { type: 'string' as const, description: 'Optional Environment ID (defaults to active session environment)' },
          query: { type: 'string' as const, description: 'Optional search keyword across clinical vignettes, guidelines, calculators, and PrimeKG pathways (e.g. sepsis, qSOFA, NSCLC, CHA2DS2-VASc)' },
          subpack: {
            type: 'string' as const,
            enum: ['all', 'open_clinical_vignettes', 'open_guidelines_vector', 'open_biomedical_kg', 'open_clinical_calculators', 'dicom_imaging_v1'] as const,
            description: 'Optional open-data sub-pack filter (default: all)'
          },
          specialty: { type: 'string' as const, description: 'Optional clinical specialty filter (e.g. icu_critical_care, cardiology_center, oncology_infusion)' }
        }
      }
    case 'get_wallet_status':
    case 'get_usage_forecast':
      return emptySchema
    case 'set_auto_reload':
      return {
        type: 'object' as const,
        required: ['enabled'],
        properties: {
          enabled: { type: 'boolean' as const, description: 'Whether auto-reload is enabled' },
          threshold_cents: { type: 'number' as const, description: 'Balance threshold in cents (minimum 100)' },
          reload_amount_cents: { type: 'number' as const, description: 'Reload amount in cents (minimum 500)' }
        }
      }
    case 'create_topup':
      return {
        type: 'object' as const,
        required: ['amount_cents'],
        properties: {
          amount_cents: { type: 'number' as const, description: 'Top-up amount in cents (minimum 500 = $5.00)' }
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

export const CLINICAL_ARCHETYPE_VALUES = [
  'ambulatory',
  'hospital',
  'cardiology',
  'ambulatory_clinic',
  'hospital_system',
  'cardiology_center',
  'emergency_trauma',
  'icu_critical_care',
  'oncology_infusion',
  'orthopedic_surgery',
  'labor_delivery_obgyn',
  'pediatrics_neonatal',
  'behavioral_health',
  'neurology_stroke',
  'nephrology_dialysis',
  'gastroenterology_endoscopy',
  'pulmonology_sleep',
  'rehabilitation_snf',
  'urgent_care_network'
] as const
