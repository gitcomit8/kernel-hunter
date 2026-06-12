"""Resource lifetime analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import networkx as nx

from kernel_hunter.analyzers.base import Analyzer, AnalyzerError
from kernel_hunter.models import AnalyzerResult, Finding, Severity
from kernel_hunter.scorers.confidence import apply_source_floor
from kernel_hunter.utils.kernel import infer_subsystem, iter_c_files


ACQUIRE_RELEASE: dict[str, str] = {
    "clk_get": "clk_put",
    "devm_clk_get": "",
    "regulator_get": "regulator_put",
    "get_device": "put_device",
    "kobject_get": "kobject_put",
    "pm_runtime_enable": "pm_runtime_disable",
    "request_irq": "free_irq",
    "ioremap": "iounmap",
}

CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
FUNC_RE = re.compile(
    r"^(?P<prefix>[A-Za-z_][\w\s\*\(\),]*?)\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{"
)


@dataclass(frozen=True)
class FunctionBlock:
    name: str
    start_line: int
    end_line: int
    text: str


@dataclass(frozen=True)
class LifetimeRule:
    acquire: str
    release: str


class ResourceLifetimeAnalyzer(Analyzer):
    """Function-local acquire/release analyzer."""

    name = "resource_lifetime"

    def __init__(self, require_tree_sitter: bool = True) -> None:
        self.require_tree_sitter = require_tree_sitter

    def run(self, kernel_tree: Path, subsystem: str | None = None) -> AnalyzerResult:
        if self.require_tree_sitter and not tree_sitter_available():
            raise AnalyzerError(
                "tree-sitter support is required for resource-lifetime scans. "
                "Install with: pip install 'kernel-hunter[c]'"
            )

        findings: list[Finding] = []
        files = iter_c_files(kernel_tree, subsystem)
        for path in files:
            relative = path.relative_to(kernel_tree).as_posix()
            findings.extend(analyze_file(path, relative))
        return AnalyzerResult(
            analyzer=self.name,
            findings=findings,
            metadata={"files": len(files), "rules": len(ACQUIRE_RELEASE)},
        )


def tree_sitter_available() -> bool:
    """Return whether tree-sitter dependencies are importable."""

    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_c  # noqa: F401
    except Exception:
        return False
    return True


def analyze_file(path: Path, relative_path: str) -> list[Finding]:
    """Analyze one C source file."""

    text = path.read_text(encoding="utf-8", errors="replace")
    findings: list[Finding] = []
    for function in extract_functions(text):
        findings.extend(analyze_function(relative_path, function))
    return findings


def extract_functions(text: str) -> list[FunctionBlock]:
    """Extract function blocks with a small brace-aware parser.

    The production command requires tree-sitter to be installed. This fallback parser is kept
    intentionally small for fixtures and resilience around parser edge cases.
    """

    lines = text.splitlines()
    functions: list[FunctionBlock] = []
    index = 0
    while index < len(lines):
        match = FUNC_RE.match(lines[index].strip())
        if not match:
            index += 1
            continue
        start = index
        depth = lines[index].count("{") - lines[index].count("}")
        end = index
        while end + 1 < len(lines) and depth > 0:
            end += 1
            depth += lines[end].count("{") - lines[end].count("}")
        functions.append(
            FunctionBlock(
                name=match.group("name"),
                start_line=start + 1,
                end_line=end + 1,
                text="\n".join(lines[start : end + 1]),
            )
        )
        index = end + 1
    return functions


def analyze_function(relative_path: str, function: FunctionBlock) -> list[Finding]:
    """Analyze function-local acquire/release symmetry."""

    calls_by_name = collect_calls(function.text)
    findings: list[Finding] = []
    cfg = build_linear_cfg(function.text)
    has_error_path = any("goto" in line or "return -" in line for line in function.text.splitlines())

    for acquire, release in ACQUIRE_RELEASE.items():
        if not release:
            continue
        acquire_lines = calls_by_name.get(acquire, [])
        if not acquire_lines:
            continue
        release_lines = calls_by_name.get(release, [])
        if len(release_lines) >= len(acquire_lines):
            continue

        first_line = function.start_line + acquire_lines[0] - 1
        confidence_bonus = 30 if has_error_path else 20
        if nx.number_of_nodes(cfg) > 1:
            confidence_bonus += 5
        finding = Finding(
            title=f"Potential missing {release} after {acquire}",
            category="resource_lifetime",
            severity=Severity.MEDIUM if has_error_path else Severity.LOW,
            confidence=0,
            subsystem=infer_subsystem(relative_path),
            file=relative_path,
            line=first_line,
            evidence=extract_line(function.text, acquire_lines[0]),
            rationale=(
                f"Function {function.name} calls {acquire} {len(acquire_lines)} time(s) "
                f"but {release} {len(release_lines)} time(s)."
            ),
            recommendation=(
                f"Audit all normal and error exits in {function.name}; add {release} where "
                "ownership is not transferred."
            ),
            source="resource_lifetime",
            analyzer="resource_lifetime",
            metadata={
                "function": function.name,
                "acquire": acquire,
                "release": release,
                "has_error_path": has_error_path,
            },
        )
        apply_source_floor(finding, "resource_lifetime", confidence_bonus)
        findings.append(finding)
    return findings


def collect_calls(text: str) -> dict[str, list[int]]:
    """Collect function calls by line number."""

    calls: dict[str, list[int]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = strip_comments(line)
        for match in CALL_RE.finditer(stripped):
            name = match.group("name")
            calls.setdefault(name, []).append(line_number)
    return calls


def strip_comments(line: str) -> str:
    """Strip simple single-line comments."""

    return line.split("//", 1)[0]


def extract_line(text: str, line_number: int) -> str:
    """Return one line from a function block."""

    lines = text.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


def build_linear_cfg(text: str) -> nx.DiGraph:
    """Build a lightweight line-level graph for evidence scoring."""

    graph = nx.DiGraph()
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        graph.add_node(index, text=line.strip())
        if index > 1:
            graph.add_edge(index - 1, index)
    return graph
