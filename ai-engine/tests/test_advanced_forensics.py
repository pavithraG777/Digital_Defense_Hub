from app.advanced_forensics import enrich_advanced_forensics
from app.media_forensics_schemas import (
    AnalysisSignal,
    MediaForensicsAssessment,
    SuspiciousRegion,
)


def test_forensics_extension_preserves_limitations_and_regions() -> None:
    assessment = MediaForensicsAssessment(
        media_type="VIDEO",
        forensic_result="SUSPICIOUS",
        confidence_score=71.0,
        noise_inconsistency_detected=True,
        frame_duplication_detected=True,
        analysis_summary="Test result",
        signals=[AnalysisSignal(code="FRAME_DUPLICATION", name="Frame duplication", category="TEMPORAL_FORENSICS", score=80, confidence=75, detected=True)],
        suspicious_locations=[SuspiciousRegion(region_type="FRAME", frame_number=12, score=80, description="Repeated frame")],
    )

    enrich_advanced_forensics(
        file_hash="a" * 64,
        media_type="VIDEO",
        deepfake=None,
        forensics=assessment,
        ocr=None,
    )

    advanced = assessment.forensic_feature_data["advanced_forensics"]
    assert advanced["media_provenance"]["verification_status"] == "SOURCE_HASH_VERIFIED"
    assert advanced["noise_sensor_forensics"]["prnu_status"] == "REQUIRES_CAMERA_REFERENCE_SET"
    assert advanced["manipulation_localization"]["status"] == "LOCALIZED"
    assert advanced["cross_modal_verification"]["status"] == "PENDING_CASE_FUSION"
