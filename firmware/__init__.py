"""X8 NIDS — production-grade, detection-only network intrusion detection system.

Blue-team tool for monitoring networks you own. Includes an offline
simulation engine so everything is testable without live packet capture.
"""

__version__ = "1.0.0"

from .config import load_config, default_config, ConfigError  # noqa: F401
from .flows import Flow  # noqa: F401
from .rules import RuleEngine, ScanRule, BruteRule, C2BeaconRule, ExfilRule  # noqa: F401
from .alert import AlertFormatter, AlertSink  # noqa: F401

__all__ = [
    "__version__",
    "load_config",
    "default_config",
    "ConfigError",
    "Flow",
    "RuleEngine",
    "ScanRule",
    "BruteRule",
    "C2BeaconRule",
    "ExfilRule",
    "AlertFormatter",
    "AlertSink",
]
