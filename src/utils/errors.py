"""Application-specific exception hierarchy."""

from typing import Optional


class VoIPAnalyzerError(Exception):
    """Base class for all application errors."""


class ValidationError(VoIPAnalyzerError):
    """Raised when user input fails validation."""

    def __init__(self, message: str, field: Optional[str] = None) -> None:
        super().__init__(message)
        self.field = field


class APIError(VoIPAnalyzerError):
    """Raised when an external API call fails."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class DatabaseError(VoIPAnalyzerError):
    """Raised on database access or migration failures."""


class PluginError(VoIPAnalyzerError):
    """Raised when a plugin fails to load or execute."""
