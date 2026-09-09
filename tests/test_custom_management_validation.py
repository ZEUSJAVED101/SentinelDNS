from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]


def test_management_has_no_dynamic_execution_primitives():
    source = (ROOT / "backend" / "api" / "management.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {"eval", "exec", "compile", "__import__"}
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not (calls & forbidden)


def test_custom_filter_has_no_dynamic_execution_primitives():
    source = (ROOT / "dns_engine" / "filters" / "custom.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {"eval", "exec", "compile", "__import__"}
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not (calls & forbidden)


def test_dashboard_query_activity_is_removed():
    source = (ROOT / "backend" / "templates" / "dashboard" / "index.html").read_text(encoding="utf-8")
    assert "Query activity" not in source
    assert 'id="query-chart"' not in source
