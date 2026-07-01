from vibesafe.scanner.report import ScanReport


def test_report_includes_repo_context():
    report = ScanReport.from_engine_result(
        scan_id="scan-123",
        repo_url="https://github.com/acme/repo",
        result={
            "risk_score": 12,
            "verdict": "LOW",
            "findings": [],
            "frameworks": ["python"],
            "repo_context": {"kind": "internal_service", "reasons": ["internal topology folder names"]},
            "files_scanned": 3,
            "scan_ms": 25,
            "models_used": [],
        },
    )

    payload = report.to_dict()

    assert payload["repo_context"]["kind"] == "internal_service"
    assert payload["frameworks"] == ["python"]
