from __future__ import annotations

from dataclasses import dataclass, field

from vibesafe.scanner.analysis.python_ast import PythonTaintAnalyzer
from vibesafe.scanner.analysis.taint import TaintGraph
from vibesafe.scanner.ingest import RepoManifest


@dataclass
class SourceFile:
    file_path: str
    language: str
    content: str


@dataclass
class CodeIndex:
    files: dict[str, SourceFile] = field(default_factory=dict)
    taint_graph: TaintGraph = field(default_factory=TaintGraph)


def build_code_index(manifest: RepoManifest) -> CodeIndex:
    index = CodeIndex()

    for path in manifest.files:
        rel = manifest.relative(path)
        content = manifest.read(path)
        if not content:
            continue

        language = _language_for_suffix(path.suffix.lower())
        index.files[rel] = SourceFile(file_path=rel, language=language, content=content)

        if language == "python":
            result = PythonTaintAnalyzer(rel, content).analyze()
            for flow in result.flows:
                index.taint_graph.add_flow(flow)

    return index


def _language_for_suffix(suffix: str) -> str:
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    return "text"
