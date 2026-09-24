from .detector import DetectionResult, Detector
from .errors import SecurityError
from .pipeline import ScanResult, SecurityPipeline

__all__ = [
    "DetectionResult",
    "Detector",
    "ScanResult",
    "SecurityError",
    "SecurityPipeline",
]

try:
    from .integrations.openai import DetectorAdapter, SecureOpenAI
    __all__ += ["DetectorAdapter", "SecureOpenAI"]
except ImportError:
    pass
