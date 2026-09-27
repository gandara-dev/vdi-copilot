import json
from unittest.mock import MagicMock, patch

from vdi_copilot.llm import explain_with_ollama
from vdi_copilot.models import Evidence, Finding


def test_ollama_request_is_non_streaming_and_returns_summary() -> None:
    response = MagicMock()
    response.read.return_value = json.dumps(
        {"message": {"content": json.dumps({"summary": "Check DNS first."})}}
    ).encode()
    response.__enter__.return_value = response
    finding = Finding(
        rule_id="dns",
        title="DNS failure",
        severity="high",
        confidence="high",
        evidence=("vda.log",),
        recommendations=("Check DNS.",),
    )

    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        result = explain_with_ollama([finding], [Evidence("vda.log", "DNS failed")])

    request = urlopen.call_args.args[0]
    payload = json.loads(request.data)
    assert payload["stream"] is False
    assert payload["think"] is False
    assert payload["format"] == "json"
    assert result == "Check DNS first."
