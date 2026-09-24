"""CLI entrypoints: scan text and issue canary tokens."""

from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .pipeline import ScanResult, SecurityPipeline, Severity

console = Console()


def _load_config(path: str | None) -> dict:
    if not path:
        # default minimal pipeline: prompt_injection only
        return {"detectors": {"prompt_injection": {"enabled": True, "params": {}}},
                "pipeline": {"mode": "sequential", "fail_fast": True}}
    import yaml
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _severity_color(sev: Severity) -> str:
    return {
        Severity.INFO: "cyan",
        Severity.LOW: "green",
        Severity.MEDIUM: "yellow",
        Severity.HIGH: "orange1",
        Severity.CRITICAL: "red",
    }.get(sev, "white")


def _render_result(res: ScanResult, show_normalized: bool = False) -> None:
    if not res.flagged:
        console.print(Text("OK", style="green"))
        return
    table = Table(title="Findings", show_header=True)
    table.add_column("Detector")
    table.add_column("Severity")
    table.add_column("Findings")
    for r in res.results:
        if r.flagged:
            table.add_row(
                r.detector,
                Text(r.severity.name, style=_severity_color(r.severity)),
                ", ".join(r.findings),
            )
    console.print(table)
    if show_normalized:
        norm = next((r.normalized for r in res.results if r.normalized), None)
        if norm:
            console.print(Text(f"Normalized:\n{norm}", style="dim"))


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.prompt and not args.file:
        console.print("[red]Provide --prompt or --file[/red]")
        return 2
    pipeline = SecurityPipeline.from_config(_load_config(args.config))

    if args.prompt:
        res = pipeline.scan(args.prompt)
        _render_result(res, show_normalized=args.normalized)
        return 1 if res.blocked else 0

    # file mode (JSONL: {"prompt": "..."} per line, optional {"text": "..."})
    blocked_any = False
    with open(args.file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            text = obj.get("prompt", obj.get("text", ""))
            if not text:
                continue
            res = pipeline.scan(text)
            if res.flagged:
                console.print(Text(f"[{res.max_severity.name}] {text[:80]}", style=_severity_color(res.max_severity)))
            if res.blocked:
                blocked_any = True
    return 1 if blocked_any else 0


def cmd_canary(args: argparse.Namespace) -> int:
    from .canary import Canary

    canary = Canary()
    if args.issue:
        for _ in range(args.count):
            console.print(canary.issue(args.length))
        return 0
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="open-sorcerer", description="AI prompt and output security scanner")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan prompts for injection")
    scan.add_argument("--prompt", help="Prompt text to scan")
    scan.add_argument("--file", help="JSONL file of prompts to scan")
    scan.add_argument("--config", default=None, help="Path to config.yaml")
    scan.add_argument("--normalized", action="store_true", help="Show normalized text")
    scan.set_defaults(func=cmd_scan)

    can = sub.add_parser("canary", help="Canary token utilities")
    can.add_argument("--issue", action="store_true", help="Issue canaries")
    can.add_argument("--length", type=int, default=32)
    can.add_argument("--count", type=int, default=1)
    can.set_defaults(func=cmd_canary)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]error:[/red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
