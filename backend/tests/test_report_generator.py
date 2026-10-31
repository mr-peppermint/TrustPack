import time

import pytest

from app.config import settings
from app.services import report_generator
from app.utils.errors import ReportNotFoundError


@pytest.fixture(autouse=True)
def _clear_store():
    """The report store is module-level global state; isolate each test so
    retention/expiry assertions aren't affected by other tests' reports.
    """
    report_generator._store.clear()
    report_generator._expires_at.clear()
    yield
    report_generator._store.clear()
    report_generator._expires_at.clear()


def _dummy_report() -> dict:
    return {"package": {"name": "x", "version": "1.0.0"}, "analysis_complete": True}


def test_save_and_get_report_roundtrip():
    report_id = report_generator.save_report(_dummy_report())
    fetched = report_generator.get_report(report_id)
    assert fetched["report_id"] == report_id


def test_get_nonexistent_report_raises():
    with pytest.raises(ReportNotFoundError):
        report_generator.get_report("does-not-exist")


def test_report_expires_after_ttl():
    report_id = report_generator.save_report(_dummy_report())
    assert report_generator.get_report(report_id)["report_id"] == report_id

    # Age the report past its TTL directly rather than sleeping in a test.
    report_generator._expires_at[report_id] = time.time() - 1
    with pytest.raises(ReportNotFoundError):
        report_generator.get_report(report_id)


def test_retention_limit_evicts_oldest(monkeypatch):
    monkeypatch.setattr(settings, "REPORT_RETENTION_LIMIT", 3)
    ids = [report_generator.save_report(_dummy_report()) for _ in range(5)]
    # The first two should have been evicted; the last three remain.
    for rid in ids[:2]:
        with pytest.raises(ReportNotFoundError):
            report_generator.get_report(rid)
    for rid in ids[2:]:
        assert report_generator.get_report(rid)["report_id"] == rid
