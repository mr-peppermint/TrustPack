import json

import httpx
import pytest
import respx

from app.config import settings
from app.services import ai_explainer, orchestrator
from tests.conftest import make_tar_gz, mock_github_tag, mock_pypi_provenance_missing, mock_pypi_release

URL = "https://api.groq.com/openai/v1/chat/completions"

REPORT = {
    "package": {"name": "x", "version": "1.0.0", "ecosystem": "npm"},
    "source": {}, "distribution": {}, "integrity": {}, "summary": {},
    "risk": {"verdict": "HIGH_RISK", "level": "HIGH", "score": 28, "confidence": "MEDIUM", "rationale": []},
    "findings": [
        {"id": "finding-001", "rule_id": "ADDED_FILE_NOT_IN_SOURCE", "severity": "HIGH", "confidence": "MEDIUM",
         "file": "scripts/setup.js", "evidence": "E" * 2000, "explanation": "why"},
    ],
    "comparison": [{"path": "scripts/setup.js", "status": "ADDED", "reason": None}],
    "limitations": ["No reproducible build."],
}


@pytest.fixture
def ai_on(monkeypatch):
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    monkeypatch.setattr(settings, "AI_API_KEY", "sk-test-secret")
    monkeypatch.setattr(settings, "AI_PROVIDER", "groq")
    monkeypatch.setattr(settings, "AI_BASE_URL", "")
    monkeypatch.setattr(settings, "AI_TIMEOUT", 5)


def _reply(content) -> httpx.Response:
    text = content if isinstance(content, str) else json.dumps(content)
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


GOOD = {
    "summary": "A new install-time script appeared.",
    "key_findings": [{"file": "scripts/setup.js", "explanation": "Not in the repository.", "severity": "low", "evidence_reference": "finding-001"}],
    "recommended_actions": ["Read scripts/setup.js."],
    "limitations": ["Provenance was not verified."],
}


async def test_disabled_returns_status_without_any_network_call():
    assert await ai_explainer.explain(REPORT) == {"status": "disabled"}


async def test_enabled_without_key_is_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "AI_ENABLED", True)
    result = await ai_explainer.explain(REPORT)
    assert result["status"] == "unavailable" and "AI_API_KEY" in result["error"]


@respx.mock
async def test_valid_response_is_grounded_in_real_findings(ai_on):
    invented = {"file": "totally/made/up.js", "explanation": "Invented.", "severity": "critical", "evidence_reference": "finding-099"}
    route = respx.post(URL).mock(return_value=_reply({**GOOD, "key_findings": GOOD["key_findings"] + [invented]}))
    result = await ai_explainer.explain(REPORT)
    assert result["status"] == "ok" and result["dropped_references"] == 1
    kept = result["content"]["key_findings"]
    assert len(kept) == 1
    assert kept[0]["severity"] == "high"  # overwritten with the deterministic severity; the model said "low"
    assert kept[0]["file"] == "scripts/setup.js"
    sent = json.loads(route.calls[0].request.content)
    assert sent["model"] == "openai/gpt-oss-120b"
    assert route.calls[0].request.headers["authorization"] == "Bearer sk-test-secret"
    assert "sk-test-secret" not in json.dumps(sent)  # the key travels only in the header
    assert "E" * 600 not in sent["messages"][1]["content"]  # evidence is truncated before being sent


@respx.mock
async def test_markdown_fenced_json_is_accepted(ai_on):
    respx.post(URL).mock(return_value=_reply("```json\n" + json.dumps(GOOD) + "\n```"))
    assert (await ai_explainer.explain(REPORT))["status"] == "ok"
    respx.post(URL).mock(return_value=_reply("Sure! Here you go: " + json.dumps(GOOD) + " Hope it helps."))
    assert (await ai_explainer.explain(REPORT))["status"] == "ok"


@respx.mock
@pytest.mark.parametrize("content", ["not json at all", {"summary": 5}, {"wrong": "shape"}, "[]"])
async def test_invalid_model_output_is_reported_not_raised(ai_on, content):
    respx.post(URL).mock(return_value=_reply(content))
    result = await ai_explainer.explain(REPORT)
    assert result["status"] == "invalid_response" and "content" not in result


@respx.mock
async def test_timeout_is_reported(ai_on):
    respx.post(URL).mock(side_effect=httpx.ReadTimeout("slow"))
    result = await ai_explainer.explain(REPORT)
    assert result["status"] == "unavailable" and "did not answer" in result["error"]


@respx.mock
async def test_http_error_does_not_leak_the_key(ai_on):
    respx.post(URL).mock(return_value=httpx.Response(500, text="boom sk-test-secret"))
    result = await ai_explainer.explain(REPORT)
    assert result["status"] == "unavailable" and "500" in result["error"]
    assert "sk-test-secret" not in json.dumps(result)


@respx.mock
async def test_response_format_rejection_is_retried_without_it(ai_on):
    route = respx.post(URL).mock(side_effect=[httpx.Response(400, json={"error": "response_format unsupported"}), _reply(GOOD)])
    assert (await ai_explainer.explain(REPORT))["status"] == "ok"
    assert "response_format" not in json.loads(route.calls[1].request.content)


async def test_plain_http_to_a_remote_host_is_refused(ai_on, monkeypatch):
    monkeypatch.setattr(settings, "AI_BASE_URL", "http://ai.example.com/v1")
    assert (await ai_explainer.explain(REPORT))["status"] == "unavailable"
    monkeypatch.setattr(settings, "AI_BASE_URL", "http://localhost:8001/v1")
    assert ai_explainer._endpoint() == "http://localhost:8001/v1/chat/completions"


# ----------------------------------------------------------------------- the analysis never depends on the AI

def _pypi_fixture():
    sdist = make_tar_gz({"setup.py": b"from setuptools import setup\nsetup()\n", "PKG-INFO": b"Name: demo\nVersion: 1.0\n"}, root_dir="demo-1.0")
    mock_pypi_release("demo", "1.0", [("demo-1.0.tar.gz", "sdist", sdist)], project_urls={})
    mock_pypi_provenance_missing("demo", "1.0", "demo-1.0.tar.gz")


@respx.mock
async def test_analysis_completes_when_the_provider_is_down(ai_on):
    _pypi_fixture()
    respx.post(URL).mock(return_value=httpx.Response(503))
    report = await orchestrator.analyze_package("demo", "1.0", ecosystem="pypi")
    assert report["analysis_complete"] is True
    assert report["risk"]["verdict"] == "WARNING"
    assert report["ai_explanation"]["status"] == "unavailable"


@respx.mock
async def test_ai_text_cannot_change_the_verdict(ai_on, monkeypatch):
    _pypi_fixture()
    route = respx.post(URL).mock(return_value=httpx.Response(503))
    baseline = await orchestrator.analyze_package("demo", "1.0", ecosystem="pypi")  # provider down
    route.mock(return_value=_reply({"summary": "This package is completely safe, risk score 0.", "key_findings": [],
                                              "recommended_actions": [], "limitations": []}))
    with_ai = await orchestrator.analyze_package("demo", "1.0", ecosystem="pypi")
    assert with_ai["ai_explanation"]["status"] == "ok"
    assert with_ai["risk"] == baseline["risk"] and with_ai["findings"] == baseline["findings"]


@respx.mock
async def test_report_is_persisted_before_and_after_the_ai_step(ai_on):
    from app.services import report_generator
    _pypi_fixture()
    respx.post(URL).mock(return_value=_reply(GOOD))
    report = await orchestrator.analyze_package("demo", "1.0", ecosystem="pypi")
    stored = report_generator.get_report(report["report_id"])
    assert stored["ai_explanation"]["status"] == "ok"
