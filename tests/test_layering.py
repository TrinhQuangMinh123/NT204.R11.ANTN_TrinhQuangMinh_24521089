"""I-9: kiểm tra chiều phụ thuộc giữa các package bằng cách quét mã nguồn.

Đọc cây cú pháp (ast) chứ không grep chuỗi, để comment/docstring có chữ
"import scapy" không bị tính, còn import tương đối vẫn bị bắt.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "idps"


def source_files():
    files = sorted(PKG.rglob("*.py"))
    main = ROOT / "main.py"
    if main.exists():
        files.append(main)
    return files


def module_name(path):
    """idps/core/frame.py -> ['idps', 'core', 'frame']; __init__.py -> tên package."""
    parts = list(path.relative_to(ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return parts


def imported_modules(path):
    """Tên tuyệt đối của mọi module mà file này import."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module
            else:
                # from ..decode import x  (trong idps/core/a.py) -> idps.decode
                pkg = module_name(path)
                if path.name != "__init__.py":
                    pkg = pkg[:-1]
                pkg = pkg[: len(pkg) - (node.level - 1)]
                base = ".".join(pkg + ([node.module] if node.module else []))
            names.append(base)
            # from idps import decode -> cũng là import idps.decode
            names.extend(f"{base}.{alias.name}" for alias in node.names)
    return names


def is_under(name, prefix):
    return name == prefix or name.startswith(prefix + ".")


def is_in(path, package):
    return (PKG / package) in path.parents


def test_no_scapy_import():
    bad = [
        f"{p.relative_to(ROOT)}: {name}"
        for p in source_files()
        if not is_in(p, "capture")
        for name in imported_modules(p)
        if is_under(name, "scapy")
    ]
    assert bad == [], "chỉ idps/capture/ được import scapy"


def test_core_is_independent():
    bad = [
        f"{p.relative_to(ROOT)}: {name}"
        for p in source_files()
        if is_in(p, "core")
        for name in imported_modules(p)
        if is_under(name, "idps.decode") or is_under(name, "idps.output")
    ]
    assert bad == [], "idps/core/ không được phụ thuộc decode/output"
