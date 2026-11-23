"""Deterministic archive-to-model and private-report builders."""

__version__ = "0.1.0"

from .output import build_report  # noqa: E402
from .report import ReportError, build_model  # noqa: E402
from .validate import validate_model  # noqa: E402

__all__ = ["ReportError", "__version__", "build_model", "build_report", "validate_model"]
