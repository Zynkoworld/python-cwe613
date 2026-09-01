"""python-cwe613 -- JWT encoded from a LITERAL payload that carries no expiration claim.

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff the line contains a `jwt.encode(...)` (or `.encode(...)`
on a jwt-like object) whose payload argument is a DICT LITERAL that has no `exp` key. If the payload is
a name, a call, or anything else the decider cannot see into, the verdict is SAFE -- no guessing.

Scope: this decides the presence of the `exp` claim in a literal payload. It does not evaluate whether a
present `exp` is a SENSIBLE lifetime, and it says nothing about server-side session stores.
stdlib `ast` only; no code is executed.
"""
import ast

CWE = "CWE-613"

_EXPIRY_KEYS = {"exp", "expires", "expiry", "expires_at", "expiration"}


def _is_jwt_encode(node):
    f = node.func
    if not isinstance(f, ast.Attribute) or f.attr != "encode":
        return False
    base = f.value
    if isinstance(base, ast.Name):
        return "jwt" in base.id.lower()
    if isinstance(base, ast.Attribute):
        return "jwt" in base.attr.lower()
    return False


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node, "lineno", None) != line:
            continue
        if not _is_jwt_encode(node):
            continue
        payload = node.args[0] if node.args else None
        if payload is None:
            for k in node.keywords:
                if k.arg == "payload":
                    payload = k.value
        if not isinstance(payload, ast.Dict):
            continue
        keys = {k.value for k in payload.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if not (keys & _EXPIRY_KEYS):
            return "FLAG"
    return "SAFE"
