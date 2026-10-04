"""代表授权与回避治理服务。"""

from .errors import (
    Conflict,
    Forbidden,
    GovernanceError,
    InvalidState,
    NotFound,
    ValidationFailed,
)
from .models import MaterialRef, Scope
from .service import GovernanceService
from .storage import inspect_schema

__all__ = [
    "Conflict",
    "Forbidden",
    "GovernanceError",
    "InvalidState",
    "MaterialRef",
    "NotFound",
    "Scope",
    "GovernanceService",
    "ValidationFailed",
    "inspect_schema",
]

__version__ = "0.1.0"
