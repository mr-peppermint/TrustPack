import pytest

from app.config import settings
from app.services import report_generator
from app.utils.errors import ReportNotFoundError


def _dummy_report(name: str = "x") -> dict:
    return {"package": {"name": name, "version": "1.0.0", "ecosystem": "npm"}, "analysis_complete": True,
            "risk": {"verdict": "VERIFIED"}}


def test_save_and_get_report_roundtrip():
    report_id = report_generator.save_report(_dummy_report())
    fetched = report_generator.get_report(report_id)
    assert fetched["report_id"] == report_id
    assert "created_at" in fetched


def test_get_nonexistent_report_raises():
    with pytest.raises(ReportNotFoundError):
        report_generator.get_report("does-not-exist")


def test_reports_survive_a_restart():
    """History is persisted in SQLite, not process memory: a fresh connection still sees the report."""
    report_id = report_generator.save_report(_dummy_report("durable"))
    from app.services import report_store
    report_store._initialized_path = None  # simulate a new process re-opening the same database file
    assert report_generator.get_report(report_id)["package"]["name"] == "durable"


def test_resaving_keeps_id_and_updates_document():
    report = _dummy_report()
    report_id = report_generator.save_report(report)
    report["risk"]["verdict"] = "WARNING"
    assert report_generator.save_report(report) == report_id
    assert report_generator.get_report(report_id)["risk"]["verdict"] == "WARNING"
    assert len(report_generator.list_reports()) == 1


def test_history_is_newest_first():
    ids = [report_generator.save_report(_dummy_report(f"pkg{i}")) for i in range(3)]
    assert [r["report_id"] for r in report_generator.list_reports()] == list(reversed(ids))


def test_retention_limit_evicts_oldest(monkeypatch):
    monkeypatch.setattr(settings, "REPORT_RETENTION_LIMIT", 3)
    ids = [report_generator.save_report(_dummy_report()) for _ in range(5)]
    for rid in ids[:2]:
        with pytest.raises(ReportNotFoundError):
            report_generator.get_report(rid)
    for rid in ids[2:]:
        assert report_generator.get_report(rid)["report_id"] == rid


def test_ttl_expires_old_reports(monkeypatch):
    report = _dummy_report()
    report["created_at"] = 1.0  # long ago
    report_id = report_generator.save_report(report)
    monkeypatch.setattr(settings, "REPORT_TTL_SECONDS", 60)
    with pytest.raises(ReportNotFoundError):
        report_generator.get_report(report_id)
