import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
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


def test_ollama_http_contract_end_to_end() -> None:
    requests: list[dict[str, object]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            length = int(self.headers["Content-Length"])
            requests.append(json.loads(self.rfile.read(length)))
            content = json.dumps({"summary": "Local mock accepted the report."})
            payload = json.dumps({"message": {"content": content}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        result = explain_with_ollama(
            [
                Finding(
                    rule_id="dns",
                    title="DNS failure",
                    severity="high",
                    confidence="high",
                    evidence=("vda.log",),
                    recommendations=("Check DNS.",),
                )
            ],
            [Evidence("vda.log", "DNS failed")],
            endpoint=f"http://127.0.0.1:{server.server_port}",
            model="acceptance-mock",
        )
    finally:
        server.server_close()
        thread.join(timeout=5)

    assert result == "Local mock accepted the report."
    assert requests[0]["model"] == "acceptance-mock"
    assert requests[0]["stream"] is False
    assert requests[0]["think"] is False
