import json
from importlib.metadata import version
from pathlib import Path

import pytest

from vdi_copilot import __version__
from vdi_copilot.cli import main

ROOT = Path(__file__).parents[1]


def test_package_versions_match() -> None:
    assert __version__ == version("vdi-copilot")


def test_analyze_json_output(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    exit_code = main(
        [
            "analyze",
            str(ROOT / "samples/incidents/vda-registration-dns"),
            "--format",
            "json",
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert report["redacted"] is True
    assert report["findings"][0]["rule_id"] == "vda-registration-dns"


def test_no_redact_requires_explicit_acknowledgement() -> None:
    with pytest.raises(SystemExit) as error:
        main(["analyze", "evidence.log", "--no-redact"])

    assert error.value.code == 2


def test_collect_requires_an_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["collect", "--output", str(tmp_path / "bundle.json")])

    assert exit_code == 2
    assert "At least one" in capsys.readouterr().err
