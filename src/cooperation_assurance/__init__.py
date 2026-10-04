"""跨境合作项目证据评估与准入服务。"""

from .contracts import Observation, Protocol, ValidationError
from .analysis import ALGORITHM_VERSION, analyze, bootstrap_mean_interval
from .governance import AuthorizationGovernance
from .numeric import NumericSummary, WilsonInterval
from .service import AssuranceService

__all__ = [
    "NumericSummary",
    "Observation",
    "Protocol",
    "ValidationError",
    "WilsonInterval",
    "ALGORITHM_VERSION",
    "AssuranceService",
    "AuthorizationGovernance",
    "analyze",
    "bootstrap_mean_interval",
]

__version__ = "0.2.0"
