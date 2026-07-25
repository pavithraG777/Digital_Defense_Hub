import math

from app.pre_encryption_schemas import (
    PreEncryptionAssessment,
    PreEncryptionFeatures,
    PreEncryptionRecommendedAction,
    PreEncryptionRequest,
    PreEncryptionRiskFactor,
)


MODEL_NAME = "DDH_PRE_ENCRYPTION_RANSOMWARE_DETECTOR"
MODEL_VERSION = "1.0.0"
POLICY_VERSION = "2026.07"


def assess_pre_encryption_risk(
    request: PreEncryptionRequest,
) -> PreEncryptionAssessment:
    features = request.features

    factors: list[PreEncryptionRiskFactor] = []

    velocity_score = _clamp_score(
        features.event_rate_per_minute
        / 60.0
        * 100.0
    )

    if features.has_rapid_file_changes:
        velocity_score = max(velocity_score, 65.0)

    if features.multiple_file_change_event_count > 0:
        velocity_score = max(velocity_score, 80.0)

    _append_factor(
        factors=factors,
        code="FILE_CHANGE_VELOCITY",
        name="File Change Velocity",
        category="BEHAVIOUR",
        description=(
            "Measures the frequency and concentration "
            "of file-system changes."
        ),
        weight=0.18,
        score=velocity_score,
        signal_count=features.total_event_count,
    )

    modification_score = _clamp_score(
        (
            features.modified_event_count
            + features.multiple_file_change_event_count
        )
        / 20.0
        * 100.0
    )

    modification_score = max(
        modification_score,
        features.modification_ratio * 100.0,
    )

    if features.has_mass_modification:
        modification_score = max(
            modification_score,
            78.0,
        )

    _append_factor(
        factors=factors,
        code="MASS_FILE_MODIFICATION",
        name="Mass File Modification",
        category="BEHAVIOUR",
        description=(
            "Measures repeated content modification "
            "across multiple files."
        ),
        weight=0.16,
        score=modification_score,
        signal_count=(
            features.modified_event_count
            + features.multiple_file_change_event_count
        ),
    )

    entropy_score = 0.0

    if features.high_entropy_write_count > 0:
        entropy_score = max(
            72.0,
            _clamp_score(
                features.high_entropy_write_count
                / features.total_event_count
                * 100.0
            ),
        )

    if features.average_entropy_after is not None:
        entropy_score = max(
            entropy_score,
            _clamp_score(
                features.average_entropy_after
                / 8.0
                * 100.0
            ),
        )

    if features.average_entropy_delta is not None:
        entropy_score = max(
            entropy_score,
            _clamp_score(
                features.average_entropy_delta
                / 2.5
                * 100.0
            ),
        )

    _append_factor(
        factors=factors,
        code="ENTROPY_TRANSFORMATION",
        name="Entropy Transformation",
        category="CONTENT",
        description=(
            "Measures entropy increases that may indicate "
            "file encryption."
        ),
        weight=0.18,
        score=entropy_score,
        signal_count=features.high_entropy_write_count,
    )

    rename_score = _clamp_score(
        max(
            features.rename_ratio,
            features.extension_change_ratio,
        )
        * 100.0
    )

    rename_score = max(
        rename_score,
        _clamp_score(
            features.renamed_event_count
            / 10.0
            * 100.0
        ),
        _clamp_score(
            features.extension_changed_event_count
            / 5.0
            * 100.0
        ),
    )

    if features.has_ransomware_extension:
        rename_score = max(rename_score, 95.0)

    _append_factor(
        factors=factors,
        code="RENAME_EXTENSION_PATTERN",
        name="Rename and Extension Pattern",
        category="FILE_SYSTEM",
        description=(
            "Measures rename bursts, extension replacement "
            "and ransomware-style extensions."
        ),
        weight=0.14,
        score=rename_score,
        signal_count=(
            features.renamed_event_count
            + features.extension_changed_event_count
            + features.ransomware_extension_count
        ),
    )

    destructive_score = max(
        _clamp_score(
            features.deleted_event_count
            / 10.0
            * 100.0
        ),
        _clamp_score(
            features.hash_changed_event_count
            / 15.0
            * 100.0
        ),
        _clamp_score(
            features.permission_changed_event_count
            / 5.0
            * 100.0
        ),
        features.deletion_ratio * 100.0,
        features.hash_change_ratio * 100.0,
    )

    _append_factor(
        factors=factors,
        code="DESTRUCTIVE_OPERATIONS",
        name="Destructive File Operations",
        category="FILE_SYSTEM",
        description=(
            "Measures deletion, hash replacement and "
            "permission manipulation."
        ),
        weight=0.10,
        score=destructive_score,
        signal_count=(
            features.deleted_event_count
            + features.hash_changed_event_count
            + features.permission_changed_event_count
        ),
    )

    deception_score = 0.0

    if (
        features.has_canary_trigger
        or features.has_honeytoken_access
    ):
        deception_score = 100.0
    elif features.has_protected_file_activity:
        deception_score = 58.0

    _append_factor(
        factors=factors,
        code="DECEPTION_INTERACTION",
        name="Deception Resource Interaction",
        category="DECEPTION",
        description=(
            "Measures access to canary files, honeytokens "
            "and protected resources."
        ),
        weight=0.12,
        score=deception_score,
        signal_count=(
            features.canary_event_count
            + features.honeytoken_event_count
            + features.protected_file_event_count
        ),
    )

    process_score = 0.0

    if features.has_suspicious_process:
        process_score = _clamp_score(
            55.0
            + features.suspicious_process_count * 10.0
        )

    _append_factor(
        factors=factors,
        code="SUSPICIOUS_PROCESS",
        name="Suspicious Process Behaviour",
        category="PROCESS",
        description=(
            "Measures destructive file activity associated "
            "with suspicious system processes."
        ),
        weight=0.06,
        score=process_score,
        signal_count=features.suspicious_process_count,
    )

    threat_signal_score = max(
        float(features.maximum_existing_threat_score),
        features.suspicious_event_ratio * 100.0,
    )

    if (
        features.suspicious_event_ratio >= 0.5
        and threat_signal_score < 72.0
    ):
        threat_signal_score = 72.0

    _append_factor(
        factors=factors,
        code="EXISTING_THREAT_CONTEXT",
        name="Existing Threat Context",
        category="THREAT",
        description=(
            "Uses suspicious-event flags and existing "
            "file-event threat scores."
        ),
        weight=0.06,
        score=threat_signal_score,
        signal_count=features.suspicious_event_count,
    )

    ai_score = sum(
        factor.contribution
        for factor in factors
    )

    correlation_bonus = _calculate_correlation_bonus(
        features,
    )

    if correlation_bonus > 0:
        factors.append(
            PreEncryptionRiskFactor(
                code="CORRELATED_BEHAVIOUR_BONUS",
                name="Correlated Ransomware Behaviour",
                category="CORRELATION",
                description=(
                    "Multiple independent ransomware "
                    "indicators occurred together."
                ),
                weight=1.0,
                score=correlation_bonus,
                contribution=correlation_bonus,
                signal_count=_active_signal_count(
                    features
                ),
            )
        )

        ai_score += correlation_bonus

    ai_score = _clamp_score(ai_score)

    policy_floor, policy_reason = (
        _calculate_policy_floor(features)
    )

    if policy_floor > ai_score:
        floor_contribution = _round_score(
            policy_floor - ai_score
        )

        factors.append(
            PreEncryptionRiskFactor(
                code="POLICY_ESCALATION_FLOOR",
                name="Security Policy Escalation",
                category="POLICY",
                description=policy_reason,
                weight=1.0,
                score=floor_contribution,
                contribution=floor_contribution,
                signal_count=1,
            )
        )

        ai_score = policy_floor

    ai_score = _round_score(ai_score)

    combined_risk_score = _round_score(
        request.rule_score * 0.45
        + ai_score * 0.55
    )

    if policy_floor > combined_risk_score:
        combined_risk_score = policy_floor

    combined_risk_score = _round_score(
        _clamp_score(combined_risk_score)
    )

    risk_level = _risk_level_from_score(
        combined_risk_score
    )

    classification = _classification_from_score(
        combined_risk_score
    )

    detection_stage = _detection_stage(
        features
    )

    threat_probability = (
        _calculate_threat_probability(
            combined_risk_score,
            features,
        )
    )

    confidence_score = _calculate_confidence(
        features,
        factors,
    )

    requires_human_review = (
        combined_risk_score >= 50.0
        or features.has_canary_trigger
        or features.has_honeytoken_access
    )

    requires_endpoint_isolation = (
        combined_risk_score >= 75.0
        or features.has_encryption_activity
        or features.has_canary_trigger
        or features.has_honeytoken_access
    )

    recommended_actions = _recommended_actions(
        features=features,
        combined_score=combined_risk_score,
    )

    explanation = _build_explanation(
        score=combined_risk_score,
        risk_level=risk_level,
        classification=classification,
        factors=factors,
        policy_reason=policy_reason,
    )

    return PreEncryptionAssessment(
        ai_score=ai_score,
        combined_risk_score=combined_risk_score,
        threat_probability=threat_probability,
        confidence_score=confidence_score,
        risk_level=risk_level,
        classification=classification,
        detection_stage=detection_stage,
        risk_factors=factors,
        recommended_actions=recommended_actions,
        score_explanation=explanation,
        requires_human_review=(
            requires_human_review
        ),
        requires_endpoint_isolation=(
            requires_endpoint_isolation
        ),
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        policy_version=POLICY_VERSION,
    )


def _append_factor(
    *,
    factors: list[PreEncryptionRiskFactor],
    code: str,
    name: str,
    category: str,
    description: str,
    weight: float,
    score: float,
    signal_count: int,
) -> None:
    score = _round_score(
        _clamp_score(score)
    )

    if score <= 0:
        return

    contribution = _round_score(
        score * weight
    )

    factors.append(
        PreEncryptionRiskFactor(
            code=code,
            name=name,
            category=category,
            description=description,
            weight=weight,
            score=score,
            contribution=contribution,
            signal_count=signal_count,
        )
    )


def _calculate_correlation_bonus(
    features: PreEncryptionFeatures,
) -> float:
    bonus = 0.0

    if (
        features.has_mass_modification
        and features.has_high_entropy_writes
    ):
        bonus += 16.0

    if (
        features.has_rapid_file_changes
        and features.has_extension_change_burst
    ):
        bonus += 10.0

    if (
        features.has_rapid_rename
        and features.has_ransomware_extension
    ):
        bonus += 10.0

    if (
        features.has_suspicious_process
        and (
            features.has_deletion_burst
            or features.has_permission_change_burst
        )
    ):
        bonus += 8.0

    if (
        features.has_canary_trigger
        or features.has_honeytoken_access
    ):
        bonus += 12.0

    if features.has_encryption_activity:
        bonus += 20.0

    return _round_score(
        min(bonus, 30.0)
    )


def _calculate_policy_floor(
    features: PreEncryptionFeatures,
) -> tuple[float, str]:
    floors: list[tuple[float, str]] = []

    if features.has_encryption_activity:
        floors.append(
            (
                96.0,
                "Explicit encrypted file activity "
                "was detected.",
            )
        )

    if (
        features.has_mass_modification
        and features.has_high_entropy_writes
    ):
        floors.append(
            (
                90.0,
                "Mass modification occurred together "
                "with high entropy writes.",
            )
        )

    if (
        features.has_canary_trigger
        or features.has_honeytoken_access
    ):
        floors.append(
            (
                84.0,
                "A deception resource was accessed "
                "or modified.",
            )
        )

    if (
        features.has_ransomware_extension
        and features.has_rapid_file_changes
    ):
        floors.append(
            (
                82.0,
                "Ransomware-style extensions appeared "
                "during rapid file changes.",
            )
        )

    if (
        features.has_mass_modification
        and features.has_rapid_file_changes
    ):
        floors.append(
            (
                72.0,
                "Mass modification and rapid file "
                "changes occurred together.",
            )
        )

    if not floors:
        return 0.0, ""

    return max(
        floors,
        key=lambda item: item[0],
    )


def _calculate_threat_probability(
    score: float,
    features: PreEncryptionFeatures,
) -> float:
    probability = (
        100.0
        / (
            1.0
            + math.exp(
                -(score - 50.0) / 10.0
            )
        )
    )

    if features.has_encryption_activity:
        probability = max(probability, 98.0)

    if (
        features.has_canary_trigger
        or features.has_honeytoken_access
    ):
        probability = max(probability, 92.0)

    if (
        features.has_high_entropy_writes
        and features.has_mass_modification
    ):
        probability = max(probability, 94.0)

    return _round_score(
        _clamp_score(probability)
    )


def _calculate_confidence(
    features: PreEncryptionFeatures,
    factors: list[PreEncryptionRiskFactor],
) -> float:
    confidence = 40.0

    confidence += min(
        features.total_event_count / 30.0 * 20.0,
        20.0,
    )

    confidence += min(
        features.unique_file_count / 20.0 * 15.0,
        15.0,
    )

    confidence += min(
        len(factors) * 3.0,
        15.0,
    )

    if (
        features.average_entropy_after is not None
        or features.average_entropy_delta is not None
    ):
        confidence += 5.0

    if (
        features.has_canary_trigger
        or features.has_honeytoken_access
    ):
        confidence += 10.0

    if features.has_encryption_activity:
        confidence += 10.0

    if (
        features.total_event_count == 1
        and not features.has_canary_trigger
        and not features.has_honeytoken_access
        and not features.has_encryption_activity
    ):
        confidence -= 15.0

    return _round_score(
        min(
            max(confidence, 20.0),
            99.0,
        )
    )


def _risk_level_from_score(
    score: float,
) -> str:
    if score >= 75.0:
        return "CRITICAL"

    if score >= 50.0:
        return "HIGH"

    if score >= 25.0:
        return "MEDIUM"

    return "LOW"


def _classification_from_score(
    score: float,
) -> str:
    if score >= 85.0:
        return "RANSOMWARE"

    if score >= 60.0:
        return "LIKELY_RANSOMWARE"

    if score >= 25.0:
        return "SUSPICIOUS"

    return "BENIGN"


def _detection_stage(
    features: PreEncryptionFeatures,
) -> str:
    if features.has_encryption_activity:
        return "ENCRYPTION_CONFIRMED"

    if (
        features.has_high_entropy_writes
        or features.has_ransomware_extension
        or features.has_extension_change_burst
    ):
        return "ENCRYPTION_SUSPECTED"

    return "PRE_ENCRYPTION"


def _recommended_actions(
    *,
    features: PreEncryptionFeatures,
    combined_score: float,
) -> list[PreEncryptionRecommendedAction]:
    if combined_score < 25.0:
        return [
            PreEncryptionRecommendedAction(
                code="CONTINUE_MONITORING",
                title="Continue Monitoring",
                description=(
                    "Continue monitoring the process "
                    "and file-system activity."
                ),
                priority="LOW",
                automatic=False,
            )
        ]

    actions = [
        PreEncryptionRecommendedAction(
            code="PRESERVE_FILE_EVENT_EVIDENCE",
            title="Preserve File Event Evidence",
            description=(
                "Preserve hashes, process information, "
                "command lines and affected file paths."
            ),
            priority="HIGH",
            automatic=False,
        )
    ]

    if (
        features.has_rapid_file_changes
        or features.has_mass_modification
    ):
        actions.append(
            PreEncryptionRecommendedAction(
                code="RESTRICT_WRITE_ACTIVITY",
                title="Restrict Write Activity",
                description=(
                    "Restrict write access for the "
                    "suspicious process and affected paths."
                ),
                priority="CRITICAL",
                automatic=False,
            )
        )

    if features.has_suspicious_process:
        actions.append(
            PreEncryptionRecommendedAction(
                code="SUSPEND_SUSPICIOUS_PROCESS",
                title="Suspend Suspicious Process",
                description=(
                    "Review and suspend the process "
                    "responsible for destructive activity."
                ),
                priority="CRITICAL",
                automatic=False,
            )
        )

    if (
        features.has_canary_trigger
        or features.has_honeytoken_access
    ):
        actions.append(
            PreEncryptionRecommendedAction(
                code="INVESTIGATE_DECEPTION_TRIGGER",
                title="Investigate Deception Trigger",
                description=(
                    "Investigate the process, identity "
                    "and device that triggered the resource."
                ),
                priority="CRITICAL",
                automatic=False,
            )
        )

    if combined_score >= 75.0:
        actions.append(
            PreEncryptionRecommendedAction(
                code="ISOLATE_ENDPOINT",
                title="Isolate Affected Endpoint",
                description=(
                    "Isolate the endpoint after approval "
                    "to prevent further encryption."
                ),
                priority="CRITICAL",
                automatic=False,
            )
        )

    return actions


def _build_explanation(
    *,
    score: float,
    risk_level: str,
    classification: str,
    factors: list[PreEncryptionRiskFactor],
    policy_reason: str,
) -> str:
    primary_factors = sorted(
        (
            factor
            for factor in factors
            if factor.code
            not in {
                "POLICY_ESCALATION_FLOOR",
                "CORRELATED_BEHAVIOUR_BONUS",
            }
        ),
        key=lambda factor: factor.contribution,
        reverse=True,
    )[:3]

    explanation = (
        "Pre-encryption ransomware hybrid score is "
        f"{score:.2f}/100, risk level is {risk_level}, "
        f"and classification is {classification}."
    )

    if primary_factors:
        factor_text = ", ".join(
            (
                f"{factor.name} "
                f"({factor.score:.2f}/100)"
            )
            for factor in primary_factors
        )

        explanation += (
            " Primary contributing factors are "
            f"{factor_text}."
        )

    if policy_reason:
        explanation += (
            " Security policy escalation applied: "
            f"{policy_reason}"
        )

    return explanation


def _active_signal_count(
    features: PreEncryptionFeatures,
) -> int:
    signals = [
        features.has_canary_trigger,
        features.has_honeytoken_access,
        features.has_rapid_file_changes,
        features.has_mass_modification,
        features.has_rapid_rename,
        features.has_extension_change_burst,
        features.has_deletion_burst,
        features.has_hash_change_burst,
        features.has_permission_change_burst,
        features.has_high_entropy_writes,
        features.has_encryption_activity,
        features.has_ransomware_extension,
        features.has_suspicious_process,
    ]

    return sum(
        1
        for signal in signals
        if signal
    )


def _clamp_score(
    value: float,
) -> float:
    if not math.isfinite(value):
        return 0.0

    return min(
        max(value, 0.0),
        100.0,
    )


def _round_score(
    value: float,
) -> float:
    return round(
        _clamp_score(value),
        2,
    )