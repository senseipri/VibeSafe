from __future__ import annotations

import ast
from dataclasses import dataclass

from vibesafe.scanner.analysis.taint import TaintFlow
from vibesafe.scanner.findings import EvidenceRef


@dataclass
class PythonAnalysisResult:
    flows: list[TaintFlow]


SOURCE_ATTRS = {
    "args",
    "form",
    "json",
    "headers",
    "cookies",
    "body",
    "GET",
    "POST",
    "data",
    "query_params",
    "path_params",
}
ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete", "route", "webhook"}
SANITIZER_NAMES = {
    "escape",
    "quote",
    "quote_plus",
    "shlex.quote",
    "json.dumps",
    "repr",
    "sanitize",
    "sanitize_sql",
    "quote_ident",
}


class PythonTaintAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: str, source: str) -> None:
        self.file_path = file_path
        self.source = source
        self.lines = source.splitlines()
        self.flows: list[TaintFlow] = []
        self._function_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    def analyze(self) -> PythonAnalysisResult:
        try:
            tree = ast.parse(self.source)
        except SyntaxError:
            return PythonAnalysisResult(flows=[])
        self.visit(tree)
        return PythonAnalysisResult(flows=self.flows)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        category = self._sink_category(node)
        if category:
            source_refs: list[EvidenceRef] = []
            path_refs: list[EvidenceRef] = []
            sanitizer_refs: list[EvidenceRef] = []

            for arg in node.args:
                source_refs.extend(self._collect_sources(arg))
                path_refs.extend(self._collect_path_refs(arg))
                sanitizer_refs.extend(self._collect_sanitizers(arg))

            if category == "sql_injection" and self._is_parameterized_sql(node):
                sanitizer_refs.append(self._ref("sanitizer", node.lineno, self._line(node.lineno)))

            if source_refs or self._current_function_has_route_param_source(node):
                if not source_refs:
                    source_refs = self._route_param_sources_for_node(node)
                sink_ref = self._ref("sink", node.lineno, self._line(node.lineno))
                self.flows.append(
                    TaintFlow(
                        category=category,
                        source_ref=source_refs[0],
                        sink_ref=sink_ref,
                        path_refs=path_refs,
                        sanitizer_refs=sanitizer_refs,
                        confidence=0.92 if not sanitizer_refs else 0.55,
                    )
                )

        self.generic_visit(node)

    def _sink_category(self, node: ast.Call) -> str | None:
        name = self._call_name(node)
        if name.endswith(".execute") or name.endswith(".executemany") or name.endswith(".raw"):
            return "sql_injection"
        if name in {"execute", "executemany"}:
            return "sql_injection"
        if name.startswith("subprocess.") or name in {"os.system", "os.popen", "eval", "exec"}:
            return "command_injection"
        if name.startswith("logger.") or name.startswith("logging.") or name == "print":
            return "log_injection"
        return None

    def _collect_sources(self, node: ast.AST) -> list[EvidenceRef]:
        refs: list[EvidenceRef] = []
        for child in ast.walk(node):
            if self._is_request_source(child):
                refs.append(self._ref("source", getattr(child, "lineno", 1), self._segment(child)))
            elif isinstance(child, ast.Name) and self._is_route_param(child.id):
                refs.append(self._ref("source", child.lineno, self._line(child.lineno)))
        return refs

    def _collect_path_refs(self, node: ast.AST) -> list[EvidenceRef]:
        refs: list[EvidenceRef] = []
        for child in ast.walk(node):
            if isinstance(child, (ast.JoinedStr, ast.BinOp, ast.Mod, ast.Name)):
                lineno = getattr(child, "lineno", None)
                if lineno:
                    refs.append(self._ref("path", lineno, self._line(lineno)))
        return refs[:5]

    def _collect_sanitizers(self, node: ast.AST) -> list[EvidenceRef]:
        refs: list[EvidenceRef] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self._call_name(child) in SANITIZER_NAMES:
                refs.append(self._ref("sanitizer", child.lineno, self._line(child.lineno)))
            if isinstance(child, ast.Call) and self._call_name(child).endswith(".replace"):
                refs.append(self._ref("sanitizer", child.lineno, self._line(child.lineno)))
        return refs

    def _is_request_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute) and node.attr in SOURCE_ATTRS:
            root = self._root_name(node)
            return root in {"request", "req"}
        if isinstance(node, ast.Subscript):
            return self._is_request_source(node.value)
        if isinstance(node, ast.Call):
            return self._call_name(node) in {"input", "sys.stdin.read"}
        return False

    def _current_function_has_route_param_source(self, node: ast.AST) -> bool:
        return bool(self._route_param_sources_for_node(node))

    def _route_param_sources_for_node(self, node: ast.AST) -> list[EvidenceRef]:
        function = self._current_function()
        if not function or not self._is_route_handler(function):
            return []
        names_used = {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
        refs: list[EvidenceRef] = []
        for arg in function.args.args + function.args.kwonlyargs:
            if arg.arg in names_used and arg.arg not in {"self", "request"}:
                refs.append(self._ref("source", function.lineno, self._line(function.lineno)))
        return refs

    def _is_route_param(self, name: str) -> bool:
        function = self._current_function()
        if not function or not self._is_route_handler(function):
            return False
        return name in {arg.arg for arg in function.args.args + function.args.kwonlyargs}

    def _is_route_handler(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for decorator in function.decorator_list:
            if isinstance(decorator, ast.Call):
                name = self._call_name(decorator)
            else:
                name = self._call_name(decorator)
            if name.split(".")[-1] in ROUTE_DECORATORS:
                return True
        return False

    def _is_parameterized_sql(self, node: ast.Call) -> bool:
        if len(node.args) >= 2:
            return True
        return any(keyword.arg in {"parameters", "params"} for keyword in node.keywords)

    def _current_function(self) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        return self._function_stack[-1] if self._function_stack else None

    def _call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Call):
            return self._call_name(node.func)
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _root_name(self, node: ast.AST) -> str:
        current = node
        while isinstance(current, ast.Attribute):
            current = current.value
        if isinstance(current, ast.Subscript):
            return self._root_name(current.value)
        if isinstance(current, ast.Name):
            return current.id
        return ""

    def _line(self, line_number: int) -> str:
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].strip()[:400]
        return ""

    def _segment(self, node: ast.AST) -> str:
        try:
            return ast.get_source_segment(self.source, node) or self._line(getattr(node, "lineno", 1))
        except Exception:
            return self._line(getattr(node, "lineno", 1))

    def _ref(self, kind: str, line_number: int, quote: str) -> EvidenceRef:
        return EvidenceRef(
            kind=kind,  # type: ignore[arg-type]
            file_path=self.file_path,
            line_start=max(line_number, 1),
            line_end=max(line_number, 1),
            quote=quote[:400],
        )
