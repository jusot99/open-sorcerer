from types import SimpleNamespace

from open_sorcerer import cli
from open_sorcerer.pipeline import ScanResult


class FakePipeline:
    def __init__(self, result):
        self.result = result
        self.scanned = []

    def scan(self, text):
        self.scanned.append(text)
        return self.result


def test_build_parser_scan_prompt():
    parser = cli.build_parser()

    args = parser.parse_args(["scan", "--prompt", "hello"])

    assert args.command == "scan"
    assert args.prompt == "hello"
    assert args.file is None
    assert args.normalized is False


def test_build_parser_canary():
    parser = cli.build_parser()

    args = parser.parse_args(
        ["canary", "--issue", "--length", "16", "--count", "3"]
    )

    assert args.command == "canary"
    assert args.issue is True
    assert args.length == 16
    assert args.count == 3


def test_scan_requires_prompt_or_file(capsys):
    args = cli.build_parser().parse_args(["scan"])

    assert cli.cmd_scan(args) == 2
    assert "Provide --prompt or --file" in capsys.readouterr().out


def test_scan_safe_prompt(monkeypatch):
    result = ScanResult(text="hello")

    pipeline = FakePipeline(result)
    monkeypatch.setattr(
        cli.SecurityPipeline,
        "from_config",
        lambda config: pipeline,
    )

    args = cli.build_parser().parse_args(["scan", "--prompt", "hello"])

    assert cli.cmd_scan(args) == 0
    assert pipeline.scanned == ["hello"]


def test_scan_blocked_prompt(monkeypatch):
    result = ScanResult(text="bad", blocked=True)

    pipeline = FakePipeline(result)
    monkeypatch.setattr(
        cli.SecurityPipeline,
        "from_config",
        lambda config: pipeline,
    )

    args = cli.build_parser().parse_args(["scan", "--prompt", "bad"])

    assert cli.cmd_scan(args) == 1
    assert pipeline.scanned == ["bad"]

def test_scan_file_mode_processes_prompt_and_text(tmp_path, monkeypatch):
    result = ScanResult(text="safe")
    pipeline = FakePipeline(result)

    monkeypatch.setattr(
        cli.SecurityPipeline,
        "from_config",
        lambda config: pipeline,
    )

    path = tmp_path / "prompts.jsonl"
    path.write_text(
    """{"prompt": "first prompt"}

{"text": "second prompt"}
not valid json
{"other": "ignored"}
{"prompt": ""}
""",
    encoding="utf-8",
)

    args = cli.build_parser().parse_args(["scan", "--file", str(path)])

    assert cli.cmd_scan(args) == 0
    assert pipeline.scanned == ["first prompt", "second prompt"]


def test_scan_file_mode_returns_one_when_any_entry_blocked(tmp_path, monkeypatch):
    class FilePipeline:
        def __init__(self):
            self.scanned = []

        def scan(self, text):
            self.scanned.append(text)
            return ScanResult(
                text=text,
                blocked=text == "blocked",
            )

    pipeline = FilePipeline()

    monkeypatch.setattr(
        cli.SecurityPipeline,
        "from_config",
        lambda config: pipeline,
    )

    path = tmp_path / "prompts.jsonl"
    path.write_text(
        '{"prompt": "safe"}\n{"prompt": "blocked"}\n',
        encoding="utf-8",
    )

    args = cli.build_parser().parse_args(["scan", "--file", str(path)])

    assert cli.cmd_scan(args) == 1
    assert pipeline.scanned == ["safe", "blocked"]

def test_canary_issue(capsys):
    args = cli.build_parser().parse_args(
        ["canary", "--issue", "--length", "8", "--count", "2"]
    )

    assert cli.cmd_canary(args) == 0

    output = capsys.readouterr().out
    lines = [line for line in output.splitlines() if line]

    assert len(lines) == 2
    assert all(len(line) > 8 for line in lines)

def test_scan_normalized_output(monkeypatch, capsys):
    class Result:
        def __init__(self):
            self.flagged = True
            self.blocked = False
            self.max_severity = cli.Severity.MEDIUM
            self.results = [
                type(
                    "DetectorResult",
                    (),
                    {
                        "flagged": True,
                        "detector": "prompt_injection",
                        "severity": cli.Severity.MEDIUM,
                        "findings": ["test_finding"],
                        "normalized": "normalized prompt",
                    },
                )()
            ]

    pipeline = FakePipeline(Result())
    monkeypatch.setattr(
        cli.SecurityPipeline,
        "from_config",
        lambda config: pipeline,
    )

    args = cli.build_parser().parse_args(
        ["scan", "--prompt", "original prompt", "--normalized"]
    )

    assert cli.cmd_scan(args) == 0

    output = capsys.readouterr().out
    assert "Normalized:" in output
    assert "normalized prompt" in output

def test_main_handles_exception(monkeypatch, capsys):
    def raise_error(_args):
        raise RuntimeError("test failure")

    class FakeParser:
        def parse_args(self, argv):
            return SimpleNamespace(func=raise_error)

    monkeypatch.setattr(cli, "build_parser", lambda: FakeParser())

    assert cli.main([]) == 1

    output = capsys.readouterr().out
    assert "error:" in output
    assert "test failure" in output