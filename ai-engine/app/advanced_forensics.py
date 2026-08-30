"""Evidence-safe advanced-forensics extensions for offline analysis jobs.

The output distinguishes observations from unavailable capabilities.  In
particular, PRNU/CFA needs a validated camera reference set and cross-modal
verification needs more than one modality; neither is inferred from a single
uploaded file.
"""

from __future__ import annotations

from typing import Any

from app.media_forensics_schemas import (
    DeepfakeAssessment,
    MediaForensicsAssessment,
    OCRAssessment,
)


def enrich_advanced_forensics(
    *,
    file_hash: str,
    media_type: str,
    deepfake: DeepfakeAssessment | None,
    forensics: MediaForensicsAssessment | None,
    ocr: OCRAssessment | None,
) -> list[str]:
    """Attach a normalized advanced-forensics payload to the assessment.

    Each engine job has one modality/assessment.  This function emits usable
    evidence for that job and explicitly leaves multi-item capabilities pending
    instead of manufacturing a conclusion.
    """
    signals = (
        deepfake.signals if deepfake is not None
        else forensics.signals if forensics is not None
        else []
    )
    regions = (
        deepfake.suspicious_regions if deepfake is not None
        else forensics.suspicious_locations if forensics is not None
        else []
    )
    detected = [signal for signal in signals if signal.detected]
    confidence_values = [signal.confidence for signal in detected]
    base_confidence = (
        deepfake.confidence_score if deepfake is not None
        else forensics.confidence_score if forensics is not None
        else ocr.confidence_score if ocr and ocr.confidence_score is not None
        else 0.0
    )
    evidence_confidence = round(
        min(100.0, base_confidence + min(10.0, len(detected) * 2.0)),
        2,
    )
    metadata_signals = [
        signal.code for signal in detected
        if "METADATA" in signal.category
    ]
    temporal_signals = [
        signal.code for signal in detected
        if "TEMPORAL" in signal.category
    ]
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "media_provenance": {
            "source_sha256": file_hash.lower(),
            "media_type": media_type,
            "verification_status": "SOURCE_HASH_VERIFIED",
        },
        "advanced_metadata_forensics": {
            "detected_signal_codes": metadata_signals,
            "status": "OBSERVED" if metadata_signals else "NO_METADATA_ANOMALY_OBSERVED",
        },
        "noise_sensor_forensics": {
            "noise_inconsistency_observed": bool(
                forensics and forensics.noise_inconsistency_detected
            ),
            "prnu_status": "REQUIRES_CAMERA_REFERENCE_SET",
            "cfa_status": "REQUIRES_RAW_OR_SENSOR_CALIBRATION_EVIDENCE",
        },
        "frame_temporal_forensics": {
            "status": "OBSERVED" if media_type == "VIDEO" else "NOT_APPLICABLE",
            "suspicious_region_count": len(regions),
            "temporal_signal_codes": temporal_signals,
            "frame_duplication_detected": bool(forensics and forensics.frame_duplication_detected),
            "frame_deletion_detected": bool(forensics and forensics.frame_deletion_detected),
            "timestamp_anomaly_detected": bool(forensics and forensics.timestamp_anomaly_detected),
        },
        "cross_modal_verification": {
            "status": "PENDING_CASE_FUSION",
            "reason": "A single analysis job cannot verify consistency across independent media modalities.",
        },
        "synthetic_media_attribution": {
            "status": "INCONCLUSIVE",
            "reason": "Attribution requires validated reference models, provenance records, or campaign intelligence.",
        },
        "manipulation_localization": {
            "status": "LOCALIZED" if regions else "NO_LOCALIZED_REGION",
            "regions": [region.model_dump(mode="json") for region in regions],
        },
        "explainable_ai": {
            "decision_basis": [
                {
                    "code": signal.code,
                    "category": signal.category,
                    "score": signal.score,
                    "confidence": signal.confidence,
                    "description": signal.description,
                }
                for signal in detected
            ],
            "model_limitations": [
                "Signals are evidence indicators, not proof of author identity.",
                "Unavailable sensor and cross-modal capabilities are explicitly marked pending.",
            ],
        },
        "evidence_confidence_matrix": {
            "overall_confidence": evidence_confidence,
            "base_assessment_confidence": base_confidence,
            "detected_signal_count": len(detected),
            "mean_signal_confidence": round(sum(confidence_values) / len(confidence_values), 2) if confidence_values else 0.0,
            "human_review_required": evidence_confidence < 75.0 or bool(regions),
        },
    }
    if deepfake is not None:
        deepfake.feature_data["advanced_forensics"] = payload
    elif forensics is not None:
        forensics.forensic_feature_data["advanced_forensics"] = payload
    elif ocr is not None:
        ocr.metadata["advanced_forensics"] = payload
    return [
        "PRNU/CFA is pending a validated camera reference or sensor calibration set.",
        "Cross-modal verification is pending case-level fusion of independent media items.",
        "Synthetic-media attribution is inconclusive without validated attribution evidence.",
    ]
