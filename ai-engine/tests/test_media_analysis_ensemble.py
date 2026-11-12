from app.media_analysis_service import MediaAnalysisService
from app.media_forensics_schemas import (
    DeepfakeAssessment,
    ModelExecutionSpecification,
)


def assessment(verdict: str, probability: float, faces: int) -> DeepfakeAssessment:
    return DeepfakeAssessment(
        media_type="IMAGE",
        detection_result=verdict,
        deepfake_probability=probability,
        authenticity_probability=100 - probability,
        confidence_score=90,
        faces_detected=faces,
        detection_summary="test assessment",
    )


def model(role: str, marker: str) -> ModelExecutionSpecification:
    return ModelExecutionSpecification(
        model_name=role,
        model_version="1.0.0",
        model_format="PTH",
        model_file_path=f"models/{marker}.pth",
        model_file_hash=marker * 64,
        confidence_threshold=80,
        configuration={"ensemble_role": role},
    )


def test_face_swap_result_is_not_applied_when_image_has_no_face() -> None:
    combined = MediaAnalysisService._combine_image_ensemble(
        [
            assessment("AUTHENTIC", 5, 0),
            assessment("DEEPFAKE", 98, 0),
        ],
        [model("WHOLE_IMAGE_AI", "a"), model("FACE_SWAP", "b")],
    )
    assert combined.detection_result == "AUTHENTIC"
    assert combined.feature_data["ensemble_components"][1]["applied"] is False


def test_face_swap_result_is_applied_when_a_face_is_detected() -> None:
    combined = MediaAnalysisService._combine_image_ensemble(
        [
            assessment("AUTHENTIC", 5, 1),
            assessment("LIKELY_DEEPFAKE", 84, 1),
        ],
        [model("WHOLE_IMAGE_AI", "a"), model("FACE_SWAP", "b")],
    )
    assert combined.detection_result == "SUSPICIOUS"
    assert combined.feature_data["ensemble_disagreement"] is True


def test_small_printed_face_is_not_treated_as_face_swap_evidence() -> None:
    whole = assessment("LIKELY_AUTHENTIC", 25, 1)
    face = assessment("LIKELY_DEEPFAKE", 91, 1)
    face.feature_data.update({
        "width": 1000, "height": 1000,
        "faces": [{"x": 100, "y": 100, "width": 50, "height": 50}],
    })
    combined = MediaAnalysisService._combine_image_ensemble(
        [whole, face],
        [model("WHOLE_IMAGE_AI", "a"), model("FACE_SWAP", "b")],
    )
    assert combined.detection_result == "LIKELY_AUTHENTIC"
    assert combined.feature_data["ensemble_components"][1]["applied"] is False


def test_ensemble_runtime_is_normalized_for_backend_contract() -> None:
    assert (
        MediaAnalysisService._normalize_runtime("ENSEMBLE[PYTORCH,PYTORCH]")
        == "PYTORCH"
    )
    assert (
        MediaAnalysisService._normalize_runtime(
            "ENSEMBLE[PYTORCH,ONNX_RUNTIME]"
        )
        == "HYBRID"
    )
