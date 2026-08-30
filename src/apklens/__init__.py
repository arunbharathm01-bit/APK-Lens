"""APKLens: lightweight static inspection for Android APK files."""

__version__ = "0.1.0"

from .analyzer import APKAnalyzer
from .models import AnalysisResult

__all__ = ["APKAnalyzer", "AnalysisResult", "__version__"]
