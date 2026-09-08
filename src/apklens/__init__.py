"""APKLens: lightweight static inspection for Android APK files."""

from .version import __version__

from .analyzer import APKAnalyzer
from .models import AnalysisResult

__all__ = ["APKAnalyzer", "AnalysisResult", "__version__"]
