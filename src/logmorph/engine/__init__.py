"""LogMorph core processing engine modules."""

from typing import Any

__all__ = [
    "EngineMetrics",
    "LogMorphEngine",
    "engine_metrics",
    "get_engine",
]


def __getattr__(name: str) -> Any:
    if name in ("LogMorphEngine", "EngineMetrics", "engine_metrics", "get_engine"):
        from logmorph.engine.core import (
            EngineMetrics,
            LogMorphEngine,
            engine_metrics,
            get_engine,
        )

        return {
            "LogMorphEngine": LogMorphEngine,
            "EngineMetrics": EngineMetrics,
            "engine_metrics": engine_metrics,
            "get_engine": get_engine,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
