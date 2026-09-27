import json
from pathlib import Path

from vdi_copilot.evidence import load_evidence, write_bundle
from vdi_copilot.models import Evidence
from vdi_copilot.redact import redact_text


def test_redacts_common_sensitive_identifiers() -> None:
    original = (
        "password=VerySecret! user=user@example.com host=vda01.example.test "
        "ip=192.0.2.10 path=C:\\Users\\alex\\profile sid=S-1-5-21-1-2-3-1001"
    )

    redacted = redact_text(original)

    assert "VerySecret" not in redacted
    assert "user@example.com" not in redacted
    assert "vda01.example.test" not in redacted
    assert "192.0.2.10" not in redacted
    assert "\\alex\\" not in redacted
    assert "S-1-5-21" not in redacted


def test_bundle_round_trip(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.json"
    write_bundle(bundle, [Evidence("sample.log", "safe text")], redacted=True)

    loaded = load_evidence(bundle)

    assert len(loaded) == 1
    assert loaded[0].source == "sample.log"
    assert loaded[0].text == "safe text"
    assert json.loads(bundle.read_text(encoding="utf-8"))["schema_version"] == 1
