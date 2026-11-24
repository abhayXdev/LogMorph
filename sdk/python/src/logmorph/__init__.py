"""LogMorph Python SDK - Zero-dependency telemetry and log ingestion client.

Built strictly using Python standard library modules.
"""

from logmorph.client import LogMorph
from logmorph.handler import LogMorphHandler

__all__ = ["LogMorph", "LogMorphHandler", "__version__"]
__version__ = "0.1.0"
