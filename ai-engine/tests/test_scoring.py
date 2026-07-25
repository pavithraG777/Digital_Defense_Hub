from app.schemas import IncidentRiskFeatures
from app.scoring import IncidentRiskScorer


def build_features(
    **overrides: object,
) -> IncidentRiskFeatures:
    feature_values: dict[str, object] = {
        "incident_category": "SYSTEM_ANOMALY",
        "incident_severity": "LOW",
        "incident_priority": "LOW",
        "incident_status": "OPEN",
        "detection_source": "SYSTEM",
        "data_exposure_suspected": False,
        "ransomware_suspected": False,
        "device_isolated": False,
        "evidence_preserved": False,
        "affected_record_count": 0,
        "estimated_financial_impact": 0,
        "incident_age_minutes": 0,
        "reporting_delay_minutes": 0,
        "investigation_age_minutes": 0,
        "linked_threat_count": 0,
        "critical_threat_count": 0,
        "high_threat_count": 0,
        "malicious_threat_count": 0,
        "confirmed_threat_count": 0,
        "unresolved_threat_count": 0,
        "maximum_threat_score": 0,
        "average_threat_score": 0,
        "maximum_confidence_score": 0,
        "total_threat_occurrences": 0,
        "total_affected_file_count": 0,
        "total_affected_device_count": 0,
        "file_event_count": 0,
        "suspicious_file_event_count": 0,
        "encrypted_event_count": 0,
        "multiple_file_change_event_count": 0,
        "hash_change_event_count": 0,
        "deleted_file_event_count": 0,
        "permission_change_event_count": 0,
        "canary_file_event_count": 0,
        "honeytoken_event_count": 0,
        "protected_file_event_count": 0,
        "unique_device_count": 0,
        "event_window_seconds": 0,
        "event_rate_per_minute": 0,
        "evidence_count": 0,
        "verified_evidence_count": 0,
        "tampered_evidence_count": 0,
        "has_canary_trigger": False,
        "has_honeytoken_access": False,
        "has_encryption_indicators": False,
        "has_rapid_file_changes": False,
        "has_hash_changes": False,
        "has_file_deletion": False,
        "has_permission_changes": False,
    }

    feature_values.update(overrides)

    return IncidentRiskFeatures(
        **feature_values
    )


def build_scorer() -> IncidentRiskScorer:
    return IncidentRiskScorer(
        model_name=(
            "DDH_INCIDENT_RANSOMWARE_RISK"
        ),
        model_version="1.0.0",
    )


def test_low_risk_incident() -> None:
    assessment = build_scorer().assess(
        build_features()
    )

    assert 0 <= assessment.overall_risk_score < 25
    assert assessment.risk_level == "LOW"
    assert 0 <= assessment.threat_probability <= 100
    assert assessment.risk_factors


def test_critical_canary_threat() -> None:
    assessment = build_scorer().assess(
        build_features(
            incident_category="CANARY_FILE_TRIGGER",
            incident_severity="CRITICAL",
            incident_priority="URGENT",
            detection_source="CANARY_FILE",
            linked_threat_count=1,
            critical_threat_count=1,
            malicious_threat_count=1,
            unresolved_threat_count=1,
            maximum_threat_score=100,
            average_threat_score=100,
            maximum_confidence_score=98,
            file_event_count=1,
            suspicious_file_event_count=1,
            hash_change_event_count=1,
            canary_file_event_count=1,
            has_canary_trigger=True,
            has_hash_changes=True,
        )
    )

    assert assessment.overall_risk_score >= 78
    assert assessment.risk_level == "CRITICAL"
    assert assessment.threat_probability >= 90
    assert assessment.requires_human_review is True

    factor_codes = {
        factor.code
        for factor in assessment.risk_factors
    }

    assert "DECEPTION_TRIGGER" in factor_codes
    assert "POLICY_ESCALATION_FLOOR" in factor_codes


def test_active_ransomware_behaviour() -> None:
    assessment = build_scorer().assess(
        build_features(
            incident_category="RANSOMWARE",
            incident_severity="CRITICAL",
            incident_priority="URGENT",
            ransomware_suspected=True,
            file_event_count=40,
            suspicious_file_event_count=40,
            encrypted_event_count=25,
            multiple_file_change_event_count=30,
            event_rate_per_minute=45,
            event_window_seconds=60,
            has_encryption_indicators=True,
            has_rapid_file_changes=True,
            has_hash_changes=True,
        )
    )

    assert assessment.overall_risk_score >= 90
    assert assessment.risk_level == "CRITICAL"
    assert assessment.threat_probability >= 95
    assert assessment.availability_risk_score >= 50
    assert assessment.requires_human_review is True


def test_all_scores_remain_valid() -> None:
    assessment = build_scorer().assess(
        build_features(
            data_exposure_suspected=True,
            ransomware_suspected=True,
            affected_record_count=10_000_000,
            estimated_financial_impact=100_000_000,
            linked_threat_count=100,
            critical_threat_count=100,
            malicious_threat_count=100,
            unresolved_threat_count=100,
            maximum_threat_score=100,
            average_threat_score=100,
            maximum_confidence_score=100,
            file_event_count=1_000_000,
            suspicious_file_event_count=1_000_000,
            encrypted_event_count=1_000_000,
            multiple_file_change_event_count=1_000_000,
            event_rate_per_minute=1_000_000,
            has_encryption_indicators=True,
            has_rapid_file_changes=True,
            has_canary_trigger=True,
            has_honeytoken_access=True,
        )
    )

    scores = [
        assessment.overall_risk_score,
        assessment.threat_probability,
        assessment.integrity_risk_score,
        assessment.confidentiality_risk_score,
        assessment.availability_risk_score,
        assessment.confidence_score,
    ]

    assert all(
        0 <= score <= 100
        for score in scores
    )

    assert all(
        0 <= factor.score <= 100
        and 0 <= factor.weight <= 1
        and 0 <= factor.contribution <= 100
        for factor in assessment.risk_factors
    )