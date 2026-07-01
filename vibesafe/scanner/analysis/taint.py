from __future__ import annotations

from dataclasses import dataclass, field

from vibesafe.scanner.findings import EvidenceRef


@dataclass
class TaintSource:
    name: str
    file_path: str
    line_number: int
    quote: str
    framework: str = "unknown"


@dataclass
class TaintSink:
    category: str
    file_path: str
    line_number: int
    quote: str


@dataclass
class Sanitizer:
    name: str
    file_path: str
    line_number: int
    quote: str


@dataclass
class TaintFlow:
    category: str
    source_ref: EvidenceRef
    sink_ref: EvidenceRef
    path_refs: list[EvidenceRef] = field(default_factory=list)
    sanitizer_refs: list[EvidenceRef] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def sanitized(self) -> bool:
        return bool(self.sanitizer_refs)

    def to_evidence_refs(self) -> list[EvidenceRef]:
        refs = [self.source_ref, *self.path_refs, self.sink_ref, *self.sanitizer_refs]
        deduped: dict[tuple[str, int, str, str], EvidenceRef] = {}
        for ref in refs:
            deduped[(ref.file_path, ref.line_start, ref.kind, ref.quote)] = ref
        return list(deduped.values())


class TaintGraph:
    def __init__(self) -> None:
        self.flows: list[TaintFlow] = []

    def add_flow(self, flow: TaintFlow) -> None:
        self.flows.append(flow)

    def find_flow(self, file_path: str, sink_line: int, category: str) -> TaintFlow | None:
        candidates = [
            flow
            for flow in self.flows
            if flow.category == category
            and flow.sink_ref.file_path == file_path
            and flow.sink_ref.line_start == sink_line
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda flow: flow.confidence)
