from palisade.scanner import Suppression
from palisade.simulate import render_report, run_simulation


def test_full_simulation(session):
    report = run_simulation(session, suppressions=[Suppression("AWS-IAM-001", "*", "moto")])
    assert report.baseline.active == []
    assert all(o.detected for o in report.outcomes)
    # Only the deliberately manual IAM findings remain open.
    assert {f.rule_id for f in report.after_remediation.active} == {"AWS-IAM-002", "AWS-IAM-004"}
    md = render_report(report)
    assert "6 / 6" in md and "MISSED" not in md
