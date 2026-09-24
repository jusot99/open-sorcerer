"""Scan latency benchmark: total and per layer, across input sizes.

Run: python scripts/bench.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.console import Console
from rich.table import Table

from open_sorcerer import encoding_normalizer as en
from open_sorcerer.detectors import PromptInjectionDetector
from open_sorcerer.pipeline import SecurityPipeline
from open_sorcerer.semantic import semantic_risk

_SENTENCE = "Please summarize the quarterly report and follow the documented process for review. "
_SIZES = (64, 256, 640, 2048)
_ROUNDS = 5


def _time(fn, *args):
    fn(*args)  # warmup, settles caches
    start = time.perf_counter()
    for _ in range(_ROUNDS):
        fn(*args)
    return (time.perf_counter() - start) / _ROUNDS * 1000


def main() -> None:
    detector = PromptInjectionDetector()
    pipeline = SecurityPipeline(detectors=[PromptInjectionDetector()])
    console = Console()
    table = Table(title="scan() latency (ms, avg of 5)")
    table.add_column("chars", justify="right")
    table.add_column("pipeline", justify="right")
    table.add_column("prompt_injection", justify="right")
    table.add_column("semantic", justify="right")
    table.add_column("normalize", justify="right")
    for n in _SIZES:
        text = (_SENTENCE * ((n // len(_SENTENCE)) + 1))[:n]
        table.add_row(
            str(n),
            f"{_time(pipeline.scan, text):.1f}",
            f"{_time(detector.scan, text):.1f}",
            f"{_time(semantic_risk, en.normalize(text)):.1f}",
            f"{_time(en.normalize, text):.1f}",
        )
    console.print(table)


if __name__ == "__main__":
    main()
