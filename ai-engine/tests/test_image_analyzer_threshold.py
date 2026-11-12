from app.media_image_analyzer import ImageAnalyzer


def test_default_deepfake_thresholds_remain_backward_compatible() -> None:
    assert ImageAnalyzer._deepfake_result(69.9) == "SUSPICIOUS"
    assert ImageAnalyzer._deepfake_result(70.0) == "LIKELY_DEEPFAKE"
    assert ImageAnalyzer._deepfake_result(85.0) == "DEEPFAKE"


def test_calibrated_deepfake_threshold_controls_verdict_bands() -> None:
    assert ImageAnalyzer._deepfake_result(39.9, 75.0) == "AUTHENTIC"
    assert ImageAnalyzer._deepfake_result(40.0, 75.0) == "LIKELY_AUTHENTIC"
    assert ImageAnalyzer._deepfake_result(60.0, 75.0) == "SUSPICIOUS"
    assert ImageAnalyzer._deepfake_result(75.0, 75.0) == "LIKELY_DEEPFAKE"
    assert ImageAnalyzer._deepfake_result(90.0, 75.0) == "DEEPFAKE"
