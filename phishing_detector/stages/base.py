"""Base protocol and utilities for pipeline stages."""

from __future__ import annotations

from abc import ABC, abstractmethod
import time

from phishing_detector.config import DetectorConfig
from phishing_detector.models import PipelineContext


class PipelineStage(ABC):
    """Abstract base class for every stage in the detection pipeline."""

    name: str = "base"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    def execute(self, context: PipelineContext) -> PipelineContext:
        """Run the stage while capturing execution timing telemetry."""
        start = time.perf_counter()
        try:
            return self.run(context)
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            context.stage_timings_ms[self.name] = round(elapsed_ms, 3)

    @abstractmethod
    def run(self, context: PipelineContext) -> PipelineContext:
        """Process and enrich the pipeline context in place."""
        raise NotImplementedError
