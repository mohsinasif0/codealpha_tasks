"""
mini_sast.py — a minimal static analysis scanner for Python/Flask code.
Mimics the core detection technique used by tools like Bandit:
walk the AST, flag calls/patterns known to correlate with vulnerability classes.

Not a replacement for Bandit/Semgrep in real work — written here because
this sandbox has no outbound internet to install them. Same underlying idea though.
"""
import ast
import sys

FINDINGS = []


def flag(filename, lineno, severity, rule_id, msg):
    FINDINGS.append((filename, lineno, severity, rule_id, msg))


class Visitor(ast.NodeVisitor):
    def __init__(self, filename, source_lines):
        self.filename = filename
        self.lines = source_lines

    def visit_Call(self, node):
        func = node.func
        name = getattr(func, "attr", None) or getattr(func, "id", None)

        if name == "loads" and isinstance(func, ast.Attribute) and \
           isinstance(func.value, ast.Name) and func.value.id == "pickle":
            flag(self.filename, node.lineno, "HIGH", "B301-pickle",
                 "pickle.loads() on data that may originate from user input -> insecure deserialization / RCE risk")

        if name == "md5":
            flag(self.filename, node.lineno, "MEDIUM", "B303-weak-hash",
                 "MD5 used for password hashing -> not memory-hard / crackable via rainbow tables, no salt shown")

        if name == "execute":
            # crude check: is a % or + string being executed?
            if node.args and isinstance(node.args[0], ast.BinOp):
                flag(self.filename, node.lineno, "HIGH", "B608-sql-injection",
                     "SQL query built via string concatenation/formatting -> SQL injection risk")

        self.generic_visit(node)

    def visit_Assign(self, node):
        # hardcoded secret_key
        for target in node.targets:
            attr = getattr(target, "attr", None)
            if attr == "secret_key" and isinstance(node.value, ast.Constant):
                flag(self.filename, node.lineno, "HIGH", "B105-hardcoded-secret",
                     "Flask secret_key is a hardcoded string literal -> session/cookie forgery risk if leaked")
        self.generic_visit(node)


def scan_file(path):
    with open(path) as f:
        source = f.read()
    tree = ast.parse(source, filename=path)
    Visitor(path, source.splitlines()).visit(tree)

    # simple text-based checks for things AST alone won't catch well
    for i, line in enumerate(source.splitlines(), start=1):
        if "debug=True" in line:
            flag(path, i, "MEDIUM", "B201-flask-debug",
                 "Flask app run with debug=True -> exposes interactive debugger/stack traces if reachable")
        if "render_template_string" in line:
            flag(path, i, "HIGH", "B999-template-injection-xss",
                 "render_template_string() building HTML with unescaped user content -> XSS risk")
        if ".save(save_path)" in line or "f.save(" in line:
            flag(path, i, "MEDIUM", "B999-unrestricted-upload",
                 "Uploaded file saved using client-supplied filename without validation -> path traversal / arbitrary file write")
        if "host=\"0.0.0.0\"" in line:
            flag(path, i, "LOW", "B104-bind-all-interfaces",
                 "App binds to 0.0.0.0 -> exposed on all network interfaces, not just localhost")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "app.py"
    scan_file(target)
    FINDINGS.sort(key=lambda f: f[1])
    print(f"\n=== mini_sast scan report: {target} ===\n")
    for filename, lineno, sev, rule, msg in FINDINGS:
        print(f"[{sev:6}] {filename}:{lineno}  ({rule})\n         {msg}\n")
    print(f"Total findings: {len(FINDINGS)}")
