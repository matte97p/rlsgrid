"""Unit tests for badge generation."""

from __future__ import annotations

from rlsgrid.badge import LABEL, from_fuzz_report, make_shields_json, make_svg


def test_pass_badge_is_brightgreen() -> None:
    badge = from_fuzz_report(ok=True, breaches=0, skipped=5)
    assert badge.color == "brightgreen"
    assert "no" in badge.message.lower()


def test_fail_badge_singular_vs_plural() -> None:
    one = from_fuzz_report(ok=False, breaches=1, skipped=0)
    many = from_fuzz_report(ok=False, breaches=3, skipped=0)
    assert one.message == "1 leak"
    assert many.message == "3 leaks"
    assert one.color == "critical"
    assert many.color == "critical"


def test_shields_json_matches_endpoint_schema() -> None:
    payload = make_shields_json(from_fuzz_report(ok=True, breaches=0, skipped=0))
    assert payload["schemaVersion"] == 1
    assert payload["label"] == LABEL
    assert payload["message"] == "no cross-tenant leaks"
    assert payload["color"] == "brightgreen"


def test_svg_contains_label_and_message() -> None:
    svg = make_svg(from_fuzz_report(ok=False, breaches=2, skipped=0))
    assert svg.startswith("<svg")
    assert "rlsgrid" in svg
    assert "2 leaks" in svg
    assert "#e05d44" in svg  # critical hex


def test_svg_escapes_xml_metacharacters() -> None:
    # craft a fake badge with HTML-ish content
    from rlsgrid.badge import BadgeData
    svg = make_svg(BadgeData(message='<script>"x"', color="red"))
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg
    assert "&quot;" in svg
