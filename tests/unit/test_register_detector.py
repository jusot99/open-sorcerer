from __future__ import annotations

from open_sorcerer.detectors.base import BaseDetector, DetectorResult, Severity
from open_sorcerer.pipeline import SecurityPipeline


class _FlagAll(BaseDetector):
    name = "flag_all_test_only"

    def scan(self, text: str, **kwargs: object) -> DetectorResult:
        return DetectorResult(
            detector=self.name,
            flagged=True,
            severity=Severity.MEDIUM,
            score=25.0,
            findings=["test_hit"],
        )


def test_register_detector_by_name():
    SecurityPipeline.register_detector("flag_all_test_only", _FlagAll)
    try:
        pipeline = SecurityPipeline.from_config(
            {"detectors": {"flag_all_test_only": {"enabled": True, "params": {}}}}
        )
        assert any(isinstance(d, _FlagAll) for d in pipeline.detectors)
        assert pipeline.scan("anything at all").results[0].findings == ["test_hit"]
    finally:
        SecurityPipeline.BUILTIN_DETECTORS.pop("flag_all_test_only", None)
