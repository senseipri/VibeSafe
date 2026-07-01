from __future__ import annotations

from vibesafe.scanner.findings import Finding


def contradiction_gate(findings: list[Finding]) -> list[Finding]:
    """
    Enforce hard local validation even if an LLM response is optimistic.
    """
    checked: list[Finding] = []
    for finding in findings:
        if finding.status == "confirmed":
            if not finding.evidence_refs or finding.line_number <= 0:
                finding.status = "rejected"
                finding.confidence = 0.0
                finding.proof.notes.append("Rejected by contradiction gate: missing evidence or source line.")
            elif finding.category in {"sql_injection", "command_injection"}:
                if not (
                    finding.proof.source_present
                    and finding.proof.sink_present
                    and finding.proof.path_present
                ):
                    finding.status = "rejected"
                    finding.confidence = min(finding.confidence, 0.45)
                    finding.proof.notes.append(
                        "Rejected by contradiction gate: exploit path proof is incomplete."
                    )
        checked.append(finding)
    return checked


def apply_final_scoring(finding: Finding) -> Finding:
    if finding.status != "confirmed":
        finding.cvss_score = None
        finding.cvss_vector = None
        finding.attack_chain = ""
        return finding

    if finding.category == "sql_injection":
        if finding.proof.exploitability_proven:
            finding.severity = "critical"
            finding.cvss_score = 9.3
            finding.cvss_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
            finding.attack_chain = _render_attack_chain(
                finding,
                "attacker-controlled input reaches a SQL execution sink without parameterization",
            )
        else:
            finding.severity = "high"
            finding.cvss_score = 7.1
            finding.cvss_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N"
        return finding

    if finding.category == "command_injection":
        finding.severity = "critical"
        finding.cvss_score = 9.8
        finding.cvss_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
        if finding.proof.exploitability_proven:
            finding.attack_chain = _render_attack_chain(
                finding,
                "attacker-controlled input reaches a shell execution sink",
            )
        return finding

    if finding.category == "log_injection":
        finding.severity = "low"
        finding.cvss_score = 3.1
        finding.cvss_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N"
        finding.attack_chain = ""
        return finding

    if finding.category in {"hardcoded_secret", "committed_env_file"}:
        finding.cvss_score = 8.8 if finding.severity == "critical" else 7.5
        finding.cvss_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N"
        return finding

    if finding.category == "weak_jwt":
        if "none" in finding.evidence.lower():
            finding.severity = "critical"
            finding.cvss_score = 9.1
            finding.cvss_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N"
            finding.attack_chain = _render_attack_chain(
                finding,
                "token signature verification is disabled",
            )
        else:
            finding.severity = "high"
            finding.cvss_score = 7.7
            finding.cvss_vector = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N"
        return finding

    if finding.category == "slopsquatting":
        finding.severity = "high"
        finding.cvss_score = 8.0
        finding.cvss_vector = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H"
        return finding

    if finding.status == "confirmed":
        severity_to_cvss = {
            "critical": (9.0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"),
            "high": (7.5, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N"),
            "medium": (5.5, "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N"),
            "low": (3.1, "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N"),
        }
        finding.cvss_score, finding.cvss_vector = severity_to_cvss[finding.severity]
    return finding


def _render_attack_chain(finding: Finding, condition: str) -> str:
    if not finding.proof.exploitability_proven:
        return ""
    return (
        f"Confirmed exploitability: {condition}. "
        f"Evidence is quoted at {finding.file_path}:{finding.line_number}."
    )
