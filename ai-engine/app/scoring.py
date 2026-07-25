from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from app.schemas import (
    IncidentRiskFeatures,
    RiskEngineAssessment,
    RiskFactor,
)


@dataclass(frozen=True, slots=True)
class FactorResult:
    code: str
    name: str
    category: str
    description: str
    weight: float
    score: float


class IncidentRiskScorer:
    def __init__(
        self,
        model_name: str,
        model_version: str,
    ) -> None:
        self.model_name = model_name.strip()
        self.model_version = model_version.strip()

        if not self.model_name:
            raise ValueError("model_name is required")

        if not self.model_version:
            raise ValueError("model_version is required")

    def assess(
        self,
        features: IncidentRiskFeatures,
    ) -> RiskEngineAssessment:
        factor_results = [
            self._ransomware_factor(features),
            self._threat_factor(features),
            self._file_activity_factor(features),
            self._deception_factor(features),
            self._incident_context_factor(features),
            self._response_gap_factor(features),
            self._evidence_factor(features),
            self._temporal_factor(features),
        ]

        risk_factors = [
            self._build_risk_factor(result)
            for result in factor_results
        ]

        base_score = _round_score(
            sum(
                factor.contribution
                for factor in risk_factors
            )
        )

        policy_floor, policy_reason = (
            self._calculate_policy_floor(features)
        )

        overall_risk_score = base_score

        if policy_floor > base_score:
            escalation_value = _round_score(
                policy_floor - base_score
            )

            risk_factors.append(
                RiskFactor(
                    code="POLICY_ESCALATION_FLOOR",
                    name="Security Policy Escalation",
                    category="POLICY",
                    description=policy_reason,
                    weight=1.0,
                    score=escalation_value,
                    contribution=escalation_value,
                )
            )

            overall_risk_score = _round_score(
                policy_floor
            )

        factor_scores = {
            factor.code: factor.score
            for factor in risk_factors
        }

        threat_probability = (
            self._calculate_threat_probability(
                features,
                factor_scores,
            )
        )

        integrity_risk_score = _weighted_score(
            [
                (
                    factor_scores[
                        "FILE_ACTIVITY"
                    ],
                    0.35,
                ),
                (
                    factor_scores[
                        "RANSOMWARE_BEHAVIOUR"
                    ],
                    0.25,
                ),
                (
                    factor_scores[
                        "EVIDENCE_INTEGRITY"
                    ],
                    0.20,
                ),
                (
                    factor_scores[
                        "THREAT_INTELLIGENCE"
                    ],
                    0.15,
                ),
                (
                    factor_scores[
                        "INCIDENT_CONTEXT"
                    ],
                    0.05,
                ),
            ]
        )

        confidentiality_risk_score = _weighted_score(
            [
                (
                    factor_scores[
                        "INCIDENT_CONTEXT"
                    ],
                    0.30,
                ),
                (
                    factor_scores[
                        "THREAT_INTELLIGENCE"
                    ],
                    0.25,
                ),
                (
                    factor_scores[
                        "DECEPTION_TRIGGER"
                    ],
                    0.20,
                ),
                (
                    factor_scores[
                        "RANSOMWARE_BEHAVIOUR"
                    ],
                    0.15,
                ),
                (
                    factor_scores[
                        "EVIDENCE_INTEGRITY"
                    ],
                    0.10,
                ),
            ]
        )

        availability_risk_score = _weighted_score(
            [
                (
                    factor_scores[
                        "RANSOMWARE_BEHAVIOUR"
                    ],
                    0.35,
                ),
                (
                    factor_scores[
                        "FILE_ACTIVITY"
                    ],
                    0.25,
                ),
                (
                    factor_scores[
                        "THREAT_INTELLIGENCE"
                    ],
                    0.20,
                ),
                (
                    factor_scores[
                        "RESPONSE_GAP"
                    ],
                    0.15,
                ),
                (
                    factor_scores[
                        "INCIDENT_CONTEXT"
                    ],
                    0.05,
                ),
            ]
        )

        confidence_score = (
            self._calculate_confidence_score(
                features
            )
        )

        risk_level = _risk_level_from_score(
            overall_risk_score
        )

        requires_human_review = (
            overall_risk_score >= 75
            or threat_probability >= 75
            or features.data_exposure_suspected
            or features.ransomware_suspected
            or features.tampered_evidence_count > 0
            or confidence_score < 60
        )

        score_explanation = (
            self._build_score_explanation(
                overall_risk_score,
                risk_level,
                risk_factors,
                policy_reason
                if policy_floor > base_score
                else None,
            )
        )

        recommended_action = (
            self._build_recommended_action(
                features,
                risk_level,
            )
        )

        return RiskEngineAssessment(
            overall_risk_score=overall_risk_score,
            risk_level=risk_level,
            threat_probability=threat_probability,
            integrity_risk_score=integrity_risk_score,
            confidentiality_risk_score=(
                confidentiality_risk_score
            ),
            availability_risk_score=(
                availability_risk_score
            ),
            confidence_score=confidence_score,
            risk_factors=risk_factors,
            score_explanation=score_explanation,
            recommended_action=recommended_action,
            requires_human_review=(
                requires_human_review
            ),
            model_name=self.model_name,
            model_version=self.model_version,
        )

    def _ransomware_factor(
        self,
        features: IncidentRiskFeatures,
    ) -> FactorResult:
        score = 0.0

        if features.ransomware_suspected:
            score += 40

        if (
            features.incident_category.upper()
            == "RANSOMWARE"
        ):
            score += 30

        if features.has_encryption_indicators:
            score += 35

        if features.has_rapid_file_changes:
            score += 20

        if features.has_canary_trigger:
            score += 25

        if features.has_honeytoken_access:
            score += 20

        if features.has_hash_changes:
            score += 10

        score += 15 * _scale(
            features.encrypted_event_count,
            5,
        )

        score += 10 * _scale(
            features.multiple_file_change_event_count,
            10,
        )

        return FactorResult(
            code="RANSOMWARE_BEHAVIOUR",
            name="Ransomware Behaviour Indicators",
            category="BEHAVIOUR",
            description=(
                "Measures encryption indicators, rapid file "
                "changes, deception triggers and ransomware "
                "classification signals."
            ),
            weight=0.20,
            score=_round_score(score),
        )

    def _threat_factor(
        self,
        features: IncidentRiskFeatures,
    ) -> FactorResult:
        linked_count = features.linked_threat_count

        critical_ratio = _ratio(
            features.critical_threat_count,
            linked_count,
        )
        malicious_ratio = _ratio(
            features.malicious_threat_count,
            linked_count,
        )
        confirmed_ratio = _ratio(
            features.confirmed_threat_count,
            linked_count,
        )
        unresolved_ratio = _ratio(
            features.unresolved_threat_count,
            linked_count,
        )

        score = (
            features.maximum_threat_score * 0.35
            + features.average_threat_score * 0.20
            + critical_ratio * 15
            + malicious_ratio * 12
            + confirmed_ratio * 8
            + unresolved_ratio * 10
        )

        return FactorResult(
            code="THREAT_INTELLIGENCE",
            name="Correlated Threat Severity",
            category="THREAT",
            description=(
                "Evaluates linked threat severity, malicious "
                "classification, confirmation and unresolved "
                "threat activity."
            ),
            weight=0.18,
            score=_round_score(score),
        )

    def _file_activity_factor(
        self,
        features: IncidentRiskFeatures,
    ) -> FactorResult:
        suspicious_ratio = _ratio(
            features.suspicious_file_event_count,
            features.file_event_count,
        )

        score = suspicious_ratio * 30

        if features.has_hash_changes:
            score += 18

        if features.has_file_deletion:
            score += 15

        if features.has_permission_changes:
            score += 12

        if features.has_rapid_file_changes:
            score += 15

        score += 10 * _scale(
            features.hash_change_event_count,
            10,
        )

        score += 8 * _scale(
            features.deleted_file_event_count,
            10,
        )

        score += 7 * _scale(
            features.permission_change_event_count,
            10,
        )

        score += 10 * _scale(
            features.event_rate_per_minute,
            30,
        )

        return FactorResult(
            code="FILE_ACTIVITY",
            name="Suspicious File Activity",
            category="FILE_SYSTEM",
            description=(
                "Measures suspicious file events, hash changes, "
                "deletions, permission changes and event rate."
            ),
            weight=0.14,
            score=_round_score(score),
        )

    def _deception_factor(
        self,
        features: IncidentRiskFeatures,
    ) -> FactorResult:
        score = 0.0

        if features.has_canary_trigger:
            score += 45

        if features.has_honeytoken_access:
            score += 45

        score += 15 * _scale(
            features.canary_file_event_count,
            3,
        )

        score += 15 * _scale(
            features.honeytoken_event_count,
            3,
        )

        score += 10 * _scale(
            features.protected_file_event_count,
            10,
        )

        return FactorResult(
            code="DECEPTION_TRIGGER",
            name="Deception Resource Interaction",
            category="DECEPTION",
            description=(
                "Measures canary file, honeytoken and protected "
                "file interactions that normally should not occur."
            ),
            weight=0.12,
            score=_round_score(score),
        )

    def _incident_context_factor(
        self,
        features: IncidentRiskFeatures,
    ) -> FactorResult:
        severity_score = {
            "LOW": 15,
            "MEDIUM": 40,
            "HIGH": 70,
            "CRITICAL": 100,
        }.get(
            features.incident_severity.upper(),
            30,
        )

        priority_score = {
            "LOW": 15,
            "MEDIUM": 40,
            "HIGH": 70,
            "URGENT": 100,
        }.get(
            features.incident_priority.upper(),
            30,
        )

        category_score = {
            "RANSOMWARE": 100,
            "DATA_BREACH": 95,
            "HONEYTOKEN_TRIGGER": 90,
            "CANARY_FILE_TRIGGER": 90,
            "UNAUTHORIZED_ACCESS": 80,
            "MALWARE": 75,
            "INSIDER_THREAT": 75,
            "ACCOUNT_COMPROMISE": 70,
            "SYSTEM_ANOMALY": 55,
        }.get(
            features.incident_category.upper(),
            40,
        )

        record_impact = _log_scale(
            features.affected_record_count,
            100_000,
        )

        financial_impact = _log_scale(
            features.estimated_financial_impact,
            1_000_000,
        )

        score = (
            severity_score * 0.35
            + priority_score * 0.20
            + category_score * 0.20
            + record_impact * 0.15
            + financial_impact * 0.10
        )

        if features.data_exposure_suspected:
            score = max(score, 80)

        return FactorResult(
            code="INCIDENT_CONTEXT",
            name="Incident Business Impact",
            category="IMPACT",
            description=(
                "Evaluates incident severity, priority, category, "
                "data exposure and estimated organizational impact."
            ),
            weight=0.14,
            score=_round_score(score),
        )

    def _response_gap_factor(
        self,
        features: IncidentRiskFeatures,
    ) -> FactorResult:
        score = 0.0

        if not features.device_isolated:
            score += 30

        if not features.evidence_preserved:
            score += 20

        score += 20 * _ratio(
            features.unresolved_threat_count,
            features.linked_threat_count,
        )

        if features.incident_status.upper() in {
            "OPEN",
            "ASSIGNED",
            "REOPENED",
        }:
            score += 15

        if features.investigation_age_minutes <= 0:
            score += 10
        else:
            score += 10 * _scale(
                features.investigation_age_minutes,
                720,
            )

        score += 10 * _scale(
            features.reporting_delay_minutes,
            120,
        )

        return FactorResult(
            code="RESPONSE_GAP",
            name="Incident Response Gap",
            category="RESPONSE",
            description=(
                "Measures isolation, evidence preservation, "
                "investigation delay and unresolved response gaps."
            ),
            weight=0.08,
            score=_round_score(score),
        )

    def _evidence_factor(
        self,
        features: IncidentRiskFeatures,
    ) -> FactorResult:
        if features.evidence_count <= 0:
            score = 30.0
        else:
            verified_ratio = _ratio(
                features.verified_evidence_count,
                features.evidence_count,
            )
            unverified_ratio = 1 - verified_ratio

            score = unverified_ratio * 45

        if features.tampered_evidence_count > 0:
            score += 60 * _scale(
                features.tampered_evidence_count,
                max(features.evidence_count, 1),
            )

        if not features.evidence_preserved:
            score += 20

        return FactorResult(
            code="EVIDENCE_INTEGRITY",
            name="Evidence Integrity Risk",
            category="EVIDENCE",
            description=(
                "Evaluates missing, unverified, unpreserved or "
                "tampered incident evidence."
            ),
            weight=0.07,
            score=_round_score(score),
        )

    def _temporal_factor(
        self,
        features: IncidentRiskFeatures,
    ) -> FactorResult:
        score = (
            35
            * _scale(
                features.incident_age_minutes,
                1440,
            )
            + 30
            * _scale(
                features.reporting_delay_minutes,
                120,
            )
            + 20
            * _scale(
                features.event_rate_per_minute,
                30,
            )
            + 15
            * _scale(
                features.event_window_seconds,
                3600,
            )
        )

        return FactorResult(
            code="TEMPORAL_EXPOSURE",
            name="Temporal Exposure",
            category="TIME",
            description=(
                "Measures incident duration, reporting delay, "
                "event rate and exposure window."
            ),
            weight=0.07,
            score=_round_score(score),
        )

    def _calculate_policy_floor(
        self,
        features: IncidentRiskFeatures,
    ) -> tuple[float, str]:
        policies: list[tuple[float, str]] = []

        if (
            features.has_encryption_indicators
            and features.has_rapid_file_changes
        ):
            policies.append(
                (
                    90,
                    "Active encryption indicators and rapid "
                    "file changes require critical escalation.",
                )
            )

        if (
            features.ransomware_suspected
            and features.has_encryption_indicators
        ):
            policies.append(
                (
                    88,
                    "Ransomware suspicion combined with "
                    "encryption behaviour requires critical "
                    "escalation.",
                )
            )

        if (
            (
                features.has_canary_trigger
                or features.has_honeytoken_access
            )
            and features.maximum_threat_score >= 75
        ):
            policies.append(
                (
                    78,
                    "A deception resource was triggered by a "
                    "high-confidence threat.",
                )
            )

        if (
            features.incident_severity.upper()
            == "CRITICAL"
            and features.maximum_threat_score >= 75
        ):
            policies.append(
                (
                    75,
                    "A critical incident is correlated with a "
                    "high-scoring threat.",
                )
            )

        if (
            features.tampered_evidence_count > 0
            and features.malicious_threat_count > 0
        ):
            policies.append(
                (
                    75,
                    "Tampered evidence is associated with a "
                    "malicious threat.",
                )
            )

        if (
            features.incident_severity.upper()
            == "HIGH"
            and features.maximum_threat_score >= 50
        ):
            policies.append(
                (
                    55,
                    "A high-severity incident is correlated with "
                    "a significant threat.",
                )
            )

        if not policies:
            return 0.0, ""

        return max(
            policies,
            key=lambda item: item[0],
        )

    def _calculate_threat_probability(
        self,
        features: IncidentRiskFeatures,
        factor_scores: dict[str, float],
    ) -> float:
        probability = _weighted_score(
            [
                (
                    factor_scores[
                        "RANSOMWARE_BEHAVIOUR"
                    ],
                    0.30,
                ),
                (
                    factor_scores[
                        "THREAT_INTELLIGENCE"
                    ],
                    0.25,
                ),
                (
                    factor_scores[
                        "FILE_ACTIVITY"
                    ],
                    0.20,
                ),
                (
                    factor_scores[
                        "DECEPTION_TRIGGER"
                    ],
                    0.15,
                ),
                (
                    factor_scores[
                        "INCIDENT_CONTEXT"
                    ],
                    0.10,
                ),
            ]
        )

        if (
            features.has_encryption_indicators
            and features.has_rapid_file_changes
        ):
            probability = max(probability, 95)

        elif (
            (
                features.has_canary_trigger
                or features.has_honeytoken_access
            )
            and features.maximum_threat_score >= 75
        ):
            probability = max(probability, 90)

        elif (
            features.malicious_threat_count > 0
            and features.maximum_threat_score >= 75
        ):
            probability = max(probability, 85)

        return _round_score(probability)

    def _calculate_confidence_score(
        self,
        features: IncidentRiskFeatures,
    ) -> float:
        confidence = 35.0

        if features.linked_threat_count > 0:
            confidence += 15

        if features.file_event_count > 0:
            confidence += 15

        if features.evidence_count > 0:
            confidence += 10

        if features.event_window_seconds > 0:
            confidence += 10

        confidence += (
            features.maximum_confidence_score
            * 0.10
        )

        if (
            features.has_canary_trigger
            or features.has_honeytoken_access
        ):
            confidence += 5

        if (
            features.has_encryption_indicators
            or features.ransomware_suspected
        ):
            confidence += 5

        return _round_score(confidence)

    def _build_risk_factor(
        self,
        result: FactorResult,
    ) -> RiskFactor:
        normalized_score = _round_score(
            result.score
        )
        normalized_weight = round(
            result.weight,
            4,
        )
        contribution = _round_score(
            normalized_score
            * normalized_weight
        )

        return RiskFactor(
            code=result.code,
            name=result.name,
            category=result.category,
            description=result.description,
            weight=normalized_weight,
            score=normalized_score,
            contribution=contribution,
        )

    def _build_score_explanation(
        self,
        overall_score: float,
        risk_level: str,
        risk_factors: list[RiskFactor],
        policy_reason: str | None,
    ) -> str:
        primary_factors = sorted(
            [
                factor
                for factor in risk_factors
                if factor.code
                != "POLICY_ESCALATION_FLOOR"
            ],
            key=lambda factor: factor.contribution,
            reverse=True,
        )[:3]

        factor_summary = ", ".join(
            (
                f"{factor.name} "
                f"({factor.score:.2f}/100)"
            )
            for factor in primary_factors
        )

        explanation = (
            f"Overall incident risk score is "
            f"{overall_score:.2f}/100 and is classified "
            f"as {risk_level}. Primary contributing "
            f"factors are {factor_summary}."
        )

        if policy_reason:
            explanation += (
                f" Security policy escalation applied: "
                f"{policy_reason}"
            )

        return explanation

    def _build_recommended_action(
        self,
        features: IncidentRiskFeatures,
        risk_level: str,
    ) -> str:
        actions: list[str] = []

        if risk_level == "CRITICAL":
            actions.extend(
                [
                    "Immediately isolate the affected endpoint",
                    "Restrict write access to affected locations",
                    "Preserve file-system and process evidence",
                    "Escalate to the incident response team",
                ]
            )

        elif risk_level == "HIGH":
            actions.extend(
                [
                    "Begin immediate analyst investigation",
                    "Temporarily restrict suspicious processes",
                    "Preserve available digital evidence",
                ]
            )

        elif risk_level == "MEDIUM":
            actions.extend(
                [
                    "Review correlated threats and file events",
                    "Increase monitoring of the affected device",
                ]
            )

        else:
            actions.append(
                "Continue monitoring and review if new indicators appear"
            )

        if features.has_honeytoken_access:
            actions.append(
                "Review potentially exposed credentials and access history"
            )

        if features.has_canary_trigger:
            actions.append(
                "Inspect the process that interacted with the canary file"
            )

        if features.has_encryption_indicators:
            actions.append(
                "Block suspected encryption activity after authorization"
            )

        if features.data_exposure_suspected:
            actions.append(
                "Start data exposure assessment and regulatory review"
            )

        if features.tampered_evidence_count > 0:
            actions.append(
                "Quarantine tampered evidence and verify trusted copies"
            )

        return "; ".join(actions) + "."


def _scale(
    value: float | int,
    full_scale_value: float,
) -> float:
    if value <= 0 or full_scale_value <= 0:
        return 0.0

    return float(
        np.clip(
            float(value) / full_scale_value,
            0.0,
            1.0,
        )
    )


def _ratio(
    numerator: float | int,
    denominator: float | int,
) -> float:
    if numerator <= 0 or denominator <= 0:
        return 0.0

    return float(
        np.clip(
            float(numerator) / float(denominator),
            0.0,
            1.0,
        )
    ) * 100


def _log_scale(
    value: float | int,
    reference_value: float,
) -> float:
    if value <= 0 or reference_value <= 0:
        return 0.0

    normalized_value = (
        math.log1p(float(value))
        / math.log1p(reference_value)
        * 100
    )

    return _round_score(normalized_value)


def _weighted_score(
    values: list[tuple[float, float]],
) -> float:
    scores = np.asarray(
        [item[0] for item in values],
        dtype=np.float64,
    )
    weights = np.asarray(
        [item[1] for item in values],
        dtype=np.float64,
    )

    return _round_score(
        float(np.dot(scores, weights))
    )


def _round_score(
    value: float,
) -> float:
    return float(
        round(
            float(
                np.clip(
                    value,
                    0.0,
                    100.0,
                )
            ),
            2,
        )
    )


def _risk_level_from_score(
    score: float,
) -> str:
    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"