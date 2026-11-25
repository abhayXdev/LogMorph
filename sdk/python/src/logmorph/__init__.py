"""LogMorph — Universal Log Pre-processing Framework & Telemetry Client."""

from logmorph.client import LogMorph
from logmorph.handler import LogMorphHandler

__all__ = ["LogMorph", "LogMorphHandler", "__version__"]
__version__ = "0.1.1"
