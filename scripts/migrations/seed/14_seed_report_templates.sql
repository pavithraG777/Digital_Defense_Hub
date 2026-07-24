-- ============================================================
-- FILE NAME : 14_seed_report_templates.sql
-- PURPOSE   : Insert default cyber security and
--             digital forensics report templates
-- PROJECT   : Offline-First Cyber Security and
--             Digital Forensics Platform
-- ============================================================

BEGIN;

-- ============================================================
-- VERIFY ORGANIZATION
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM organizations
        WHERE organization_code = 'CSL001'
          AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'Organization CSL001 does not exist. Run 01_seed_organization.sql first.';
    END IF;
END;
$$;

-- ============================================================
-- VERIFY SUPER ADMIN
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users u
        JOIN organizations o
            ON o.id = u.organization_id
        WHERE o.organization_code = 'CSL001'
          AND o.deleted_at IS NULL
          AND u.username = 'superadmin'
          AND u.account_status = 'ACTIVE'
          AND u.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'Active Super Admin user does not exist. Run 06_seed_admin_user.sql first.';
    END IF;
END;
$$;

-- ============================================================
-- INSERT DEFAULT REPORT TEMPLATES
-- ============================================================

INSERT INTO report_templates (
    organization_id,
    department_id,
    template_code,
    template_name,
    description,
    report_category,
    report_type,
    data_source,
    selected_fields,
    default_filters,
    sorting_configuration,
    grouping_configuration,
    chart_configuration,
    header_content,
    footer_content,
    include_organization_logo,
    requires_approval,
    contains_sensitive_data,
    status,
    created_by,
    updated_by,
    created_at,
    updated_at,
    deleted_at
)
SELECT
    o.id,
    NULL,
    template_data.template_code,
    template_data.template_name,
    template_data.description,
    template_data.report_category,
    template_data.report_type,
    template_data.data_source,
    template_data.selected_fields,
    template_data.default_filters,
    template_data.sorting_configuration,
    template_data.grouping_configuration,
    template_data.chart_configuration,
    template_data.header_content,
    template_data.footer_content,
    TRUE,
    template_data.requires_approval,
    template_data.contains_sensitive_data,
    'ACTIVE',
    admin_user.id,
    admin_user.id,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    NULL
FROM organizations o
JOIN users admin_user
    ON admin_user.organization_id = o.id
CROSS JOIN (
    VALUES

        -- ====================================================
        -- 1. INCIDENT INVESTIGATION REPORT
        -- ====================================================

        (
            'RPT001',
            'Incident Investigation Report',
            'Provides complete details about a cyber security incident, investigation findings, containment actions and final resolution.',
            'INCIDENT',
            'DETAILED',
            'MULTIPLE_SOURCES',

            jsonb_build_array(
                'incident_number',
                'incident_title',
                'incident_category',
                'severity',
                'priority',
                'status',
                'detection_source',
                'affected_device_name',
                'affected_device_identifier',
                'lead_investigator',
                'reported_by',
                'data_exposure_suspected',
                'ransomware_suspected',
                'device_isolated',
                'evidence_preserved',
                'initial_findings',
                'root_cause',
                'containment_summary',
                'resolution_summary',
                'detected_at',
                'reported_at',
                'resolved_at'
            ),

            jsonb_build_object(
                'exclude_deleted_records', TRUE,
                'include_incident_evidence', TRUE,
                'include_assignments', TRUE,
                'include_status_history', TRUE,
                'include_response_actions', TRUE
            ),

            jsonb_build_object(
                'field', 'detected_at',
                'direction', 'DESC'
            ),

            jsonb_build_object(
                'primary_group', 'incident_category',
                'secondary_group', 'severity'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'BAR',
                        'title', 'Incidents by Severity',
                        'group_by', 'severity'
                    ),
                    jsonb_build_object(
                        'type', 'PIE',
                        'title', 'Incidents by Status',
                        'group_by', 'status'
                    )
                )
            ),

            'CYBER SECURITY INCIDENT INVESTIGATION REPORT',

            'This report is confidential and intended only for authorized personnel.',

            TRUE,
            TRUE
        ),

        -- ====================================================
        -- 2. DIGITAL EVIDENCE REPORT
        -- ====================================================

        (
            'RPT002',
            'Digital Evidence Examination Report',
            'Presents collected digital evidence details, file integrity information, examination findings and investigator notes.',
            'DIGITAL_EVIDENCE',
            'FORENSIC',
            'EVIDENCE_ITEMS',

            jsonb_build_array(
                'evidence_number',
                'evidence_name',
                'evidence_type',
                'description',
                'source_type',
                'original_file_name',
                'file_size_bytes',
                'mime_type',
                'collection_method',
                'storage_location',
                'integrity_status',
                'collected_by',
                'collected_at',
                'created_at'
            ),

            jsonb_build_object(
                'exclude_deleted_records', TRUE,
                'include_hash_information', TRUE,
                'include_evidence_files', TRUE,
                'include_tags', TRUE,
                'include_analysis_results', TRUE
            ),

            jsonb_build_object(
                'field', 'collected_at',
                'direction', 'ASC'
            ),

            jsonb_build_object(
                'primary_group', 'evidence_type',
                'secondary_group', 'integrity_status'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'BAR',
                        'title', 'Evidence by Type',
                        'group_by', 'evidence_type'
                    )
                )
            ),

            'DIGITAL EVIDENCE EXAMINATION REPORT',

            'Evidence integrity must be verified before legal or investigative use.',

            TRUE,
            TRUE
        ),

        -- ====================================================
        -- 3. CHAIN OF CUSTODY REPORT
        -- ====================================================

        (
            'RPT003',
            'Evidence Chain of Custody Report',
            'Documents the complete handling, transfer, storage and access history of digital evidence.',
            'CHAIN_OF_CUSTODY',
            'FORENSIC',
            'MULTIPLE_SOURCES',

            jsonb_build_array(
                'evidence_number',
                'evidence_name',
                'custody_action',
                'transferred_from',
                'transferred_to',
                'transfer_reason',
                'storage_location',
                'received_condition',
                'released_condition',
                'action_timestamp',
                'remarks',
                'recorded_by'
            ),

            jsonb_build_object(
                'exclude_deleted_records', TRUE,
                'include_all_custody_events', TRUE,
                'include_hash_verification', TRUE,
                'include_signature_section', TRUE
            ),

            jsonb_build_object(
                'field', 'action_timestamp',
                'direction', 'ASC'
            ),

            jsonb_build_object(
                'primary_group', 'evidence_number'
            ),

            jsonb_build_object(
                'enabled', FALSE,
                'charts', jsonb_build_array()
            ),

            'DIGITAL EVIDENCE CHAIN OF CUSTODY',

            'Every evidence transfer must be signed and verified by authorized personnel.',

            TRUE,
            TRUE
        ),

        -- ====================================================
        -- 4. AI ANALYSIS REPORT
        -- ====================================================

        (
            'RPT004',
            'AI Analysis Report',
            'Shows AI model execution details, analysis results, confidence values, detected indicators and review status.',
            'AI_ANALYSIS',
            'DETAILED',
            'AI_ANALYSIS_JOBS',

            jsonb_build_array(
                'job_number',
                'analysis_type',
                'model_name',
                'model_version',
                'input_file_name',
                'execution_status',
                'confidence_score',
                'result_classification',
                'risk_level',
                'detected_indicators',
                'processing_time',
                'review_status',
                'reviewed_by',
                'started_at',
                'completed_at'
            ),

            jsonb_build_object(
                'exclude_failed_jobs', FALSE,
                'include_configuration', TRUE,
                'include_raw_results', FALSE,
                'include_model_information', TRUE
            ),

            jsonb_build_object(
                'field', 'started_at',
                'direction', 'DESC'
            ),

            jsonb_build_object(
                'primary_group', 'analysis_type',
                'secondary_group', 'execution_status'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'BAR',
                        'title', 'AI Analysis by Type',
                        'group_by', 'analysis_type'
                    ),
                    jsonb_build_object(
                        'type', 'PIE',
                        'title', 'Results by Risk Level',
                        'group_by', 'risk_level'
                    )
                )
            ),

            'ARTIFICIAL INTELLIGENCE ANALYSIS REPORT',

            'AI-generated results must be reviewed by an authorized analyst before final use.',

            TRUE,
            TRUE
        ),

        -- ====================================================
        -- 5. DEEPFAKE ANALYSIS REPORT
        -- ====================================================

        (
            'RPT005',
            'Deepfake and Synthetic Media Analysis Report',
            'Provides technical findings from image, video or audio deepfake analysis, including confidence scores and manipulation indicators.',
            'DEEPFAKE_ANALYSIS',
            'FORENSIC',
            'AI_ANALYSIS_JOBS',

            jsonb_build_array(
                'job_number',
                'media_type',
                'file_name',
                'file_hash',
                'model_name',
                'model_version',
                'classification',
                'confidence_score',
                'face_manipulation_detected',
                'synthetic_audio_detected',
                'metadata_mismatch_detected',
                'temporal_anomaly_detected',
                'analyst_conclusion',
                'reviewed_by',
                'completed_at'
            ),

            jsonb_build_object(
                'analysis_types', jsonb_build_array(
                    'DEEPFAKE_IMAGE_DETECTION',
                    'DEEPFAKE_VIDEO_DETECTION',
                    'DEEPFAKE_AUDIO_DETECTION'
                ),
                'include_frame_results', TRUE,
                'include_metadata_findings', TRUE,
                'include_confidence_explanation', TRUE
            ),

            jsonb_build_object(
                'field', 'completed_at',
                'direction', 'DESC'
            ),

            jsonb_build_object(
                'primary_group', 'media_type',
                'secondary_group', 'classification'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'GAUGE',
                        'title', 'Deepfake Confidence Score',
                        'value_field', 'confidence_score'
                    )
                )
            ),

            'DEEPFAKE AND SYNTHETIC MEDIA FORENSIC ANALYSIS',

            'This result represents AI-assisted analysis and requires expert verification.',

            TRUE,
            TRUE
        ),

        -- ====================================================
        -- 6. CYBER RISK ASSESSMENT REPORT
        -- ====================================================

        (
            'RPT006',
            'Cyber Incident Risk Assessment Report',
            'Displays calculated cyber risk scores, contributing factors, risk levels and recommended actions.',
            'RISK_ASSESSMENT',
            'STATISTICAL',
            'AI_RISK_SCORES',

            jsonb_build_array(
                'incident_number',
                'incident_title',
                'severity',
                'priority',
                'overall_risk_score',
                'risk_level',
                'data_exposure_score',
                'ransomware_score',
                'asset_impact_score',
                'evidence_score',
                'alert_confidence_score',
                'recommended_action',
                'calculated_at'
            ),

            jsonb_build_object(
                'minimum_risk_score', 0,
                'include_closed_incidents', TRUE,
                'include_risk_components', TRUE,
                'include_recommendations', TRUE
            ),

            jsonb_build_object(
                'field', 'overall_risk_score',
                'direction', 'DESC'
            ),

            jsonb_build_object(
                'primary_group', 'risk_level'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'BAR',
                        'title', 'Incidents by Risk Level',
                        'group_by', 'risk_level'
                    ),
                    jsonb_build_object(
                        'type', 'LINE',
                        'title', 'Risk Score Trend',
                        'x_axis', 'calculated_at',
                        'y_axis', 'overall_risk_score'
                    )
                )
            ),

            'CYBER SECURITY RISK ASSESSMENT REPORT',

            'Risk scores are decision-support values and must be reviewed with supporting evidence.',

            TRUE,
            TRUE
        ),

        -- ====================================================
        -- 7. SECURITY ALERT SUMMARY
        -- ====================================================

        (
            'RPT007',
            'Security Alert Summary Report',
            'Summarizes generated security alerts based on severity, source, alert category, status and response activity.',
            'SECURITY_ALERT',
            'SUMMARY',
            'SECURITY_ALERTS',

            jsonb_build_array(
                'alert_number',
                'alert_title',
                'alert_category',
                'severity',
                'priority',
                'source',
                'status',
                'affected_device',
                'affected_user',
                'confidence_score',
                'acknowledged_by',
                'acknowledged_at',
                'generated_at'
            ),

            jsonb_build_object(
                'exclude_deleted_records', TRUE,
                'include_acknowledged_alerts', TRUE,
                'include_resolved_alerts', TRUE
            ),

            jsonb_build_object(
                'field', 'generated_at',
                'direction', 'DESC'
            ),

            jsonb_build_object(
                'primary_group', 'severity',
                'secondary_group', 'status'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'PIE',
                        'title', 'Alerts by Severity',
                        'group_by', 'severity'
                    ),
                    jsonb_build_object(
                        'type', 'BAR',
                        'title', 'Alerts by Category',
                        'group_by', 'alert_category'
                    )
                )
            ),

            'SECURITY ALERT SUMMARY REPORT',

            'Generated by the Offline Cyber Security Monitoring Platform.',

            TRUE,
            FALSE
        ),

        -- ====================================================
        -- 8. HONEYTOKEN ACTIVITY REPORT
        -- ====================================================

        (
            'RPT008',
            'Honeytoken Activity Report',
            'Reports honeytoken access attempts, trigger details, suspicious identities and related incident information.',
            'HONEYTOKEN',
            'DETAILED',
            'HONEYTOKEN_LOGS',

            jsonb_build_array(
                'honeytoken_code',
                'honeytoken_name',
                'honeytoken_type',
                'trigger_event',
                'source_ip_address',
                'device_name',
                'username',
                'process_name',
                'file_path',
                'risk_level',
                'incident_number',
                'triggered_at'
            ),

            jsonb_build_object(
                'include_all_triggers', TRUE,
                'include_source_information', TRUE,
                'include_linked_incidents', TRUE
            ),

            jsonb_build_object(
                'field', 'triggered_at',
                'direction', 'DESC'
            ),

            jsonb_build_object(
                'primary_group', 'honeytoken_type',
                'secondary_group', 'risk_level'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'BAR',
                        'title', 'Honeytoken Triggers by Type',
                        'group_by', 'honeytoken_type'
                    )
                )
            ),

            'HONEYTOKEN SECURITY ACTIVITY REPORT',

            'Any honeytoken access must be treated as potentially unauthorized activity.',

            TRUE,
            TRUE
        ),

        -- ====================================================
        -- 9. CANARY FILE ACTIVITY REPORT
        -- ====================================================

        (
            'RPT009',
            'Canary File Activity Report',
            'Shows canary file access, modification, deletion or encryption events used for early ransomware detection.',
            'CANARY_FILE',
            'DETAILED',
            'CANARY_FILE_LOGS',

            jsonb_build_array(
                'canary_file_code',
                'canary_file_name',
                'file_path',
                'event_type',
                'previous_hash',
                'current_hash',
                'process_name',
                'username',
                'device_name',
                'ransomware_suspected',
                'incident_number',
                'detected_at'
            ),

            jsonb_build_object(
                'include_access_events', TRUE,
                'include_modification_events', TRUE,
                'include_deletion_events', TRUE,
                'include_encryption_events', TRUE,
                'include_linked_incidents', TRUE
            ),

            jsonb_build_object(
                'field', 'detected_at',
                'direction', 'DESC'
            ),

            jsonb_build_object(
                'primary_group', 'event_type',
                'secondary_group', 'ransomware_suspected'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'PIE',
                        'title', 'Canary File Events',
                        'group_by', 'event_type'
                    )
                )
            ),

            'CANARY FILE RANSOMWARE DETECTION REPORT',

            'Canary file changes must be investigated immediately for possible ransomware activity.',

            TRUE,
            TRUE
        ),

        -- ====================================================
        -- 10. MANAGEMENT EXECUTIVE SUMMARY
        -- ====================================================

        (
            'RPT010',
            'Cyber Security Executive Summary Report',
            'Provides management-level statistics about incidents, alerts, evidence, AI analysis and organizational cyber risk.',
            'MANAGEMENT_SUMMARY',
            'MANAGEMENT',
            'MULTIPLE_SOURCES',

            jsonb_build_array(
                'reporting_period',
                'total_incidents',
                'critical_incidents',
                'open_incidents',
                'resolved_incidents',
                'total_security_alerts',
                'high_risk_alerts',
                'total_evidence_items',
                'ai_analyses_completed',
                'deepfake_cases_detected',
                'ransomware_cases_detected',
                'honeytoken_triggers',
                'canary_file_triggers',
                'average_resolution_time',
                'overall_risk_level'
            ),

            jsonb_build_object(
                'reporting_period', 'CURRENT_MONTH',
                'include_incident_statistics', TRUE,
                'include_alert_statistics', TRUE,
                'include_ai_statistics', TRUE,
                'include_risk_summary', TRUE
            ),

            jsonb_build_object(
                'field', 'reporting_period',
                'direction', 'DESC'
            ),

            jsonb_build_object(
                'primary_group', 'reporting_period'
            ),

            jsonb_build_object(
                'enabled', TRUE,
                'charts', jsonb_build_array(
                    jsonb_build_object(
                        'type', 'LINE',
                        'title', 'Incident Trend',
                        'x_axis', 'reporting_period',
                        'y_axis', 'total_incidents'
                    ),
                    jsonb_build_object(
                        'type', 'PIE',
                        'title', 'Incident Status Summary',
                        'group_by', 'incident_status'
                    ),
                    jsonb_build_object(
                        'type', 'BAR',
                        'title', 'Security Detection Summary',
                        'group_by', 'detection_source'
                    )
                )
            ),

            'CYBER SECURITY MANAGEMENT EXECUTIVE SUMMARY',

            'Prepared for authorized management review. Detailed technical information is available in the supporting reports.',

            TRUE,
            FALSE
        )

) AS template_data (
    template_code,
    template_name,
    description,
    report_category,
    report_type,
    data_source,
    selected_fields,
    default_filters,
    sorting_configuration,
    grouping_configuration,
    chart_configuration,
    header_content,
    footer_content,
    requires_approval,
    contains_sensitive_data
)
WHERE o.organization_code = 'CSL001'
  AND o.deleted_at IS NULL
  AND admin_user.username = 'superadmin'
  AND admin_user.account_status = 'ACTIVE'
  AND admin_user.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM report_templates existing_template
      WHERE existing_template.organization_id = o.id
        AND (
            existing_template.template_code =
                template_data.template_code
            OR
            existing_template.template_name =
                template_data.template_name
        )
  );

COMMIT;

-- ============================================================
-- VERIFY INSERTED REPORT TEMPLATES
-- ============================================================

SELECT
    rt.template_code,
    rt.template_name,
    rt.report_category,
    rt.report_type,
    rt.data_source,
    rt.requires_approval,
    rt.contains_sensitive_data,
    rt.status,
    u.username AS created_by,
    rt.created_at
FROM report_templates rt
JOIN organizations o
    ON o.id = rt.organization_id
LEFT JOIN users u
    ON u.id = rt.created_by
WHERE o.organization_code = 'CSL001'
  AND rt.deleted_at IS NULL
ORDER BY rt.template_code;

-- ============================================================
-- VERIFY TOTAL COUNT
-- ============================================================

SELECT
    COUNT(*) AS total_report_templates
FROM report_templates rt
JOIN organizations o
    ON o.id = rt.organization_id
WHERE o.organization_code = 'CSL001'
  AND rt.deleted_at IS NULL;

-- Expected result:
-- total_report_templates = 10

-- ============================================================
-- COUNT BY REPORT CATEGORY
-- ============================================================

SELECT
    rt.report_category,
    COUNT(*) AS total_templates
FROM report_templates rt
JOIN organizations o
    ON o.id = rt.organization_id
WHERE o.organization_code = 'CSL001'
  AND rt.deleted_at IS NULL
GROUP BY rt.report_category
ORDER BY rt.report_category;

-- ============================================================
-- END OF DATABASE SEED FILES
-- ============================================================