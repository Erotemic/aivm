"""Enumerate every CommandManager command submission and its declared role.

Reports each `.run(...)` / `.submit(...)` call with the role it declares (or
inherits from an enclosing intent/step), so the approval-policy audit works
from the real call sites rather than from grep guesses.
"""

import ast
import json
import sys
from pathlib import Path

ROOT = Path('/home/joncrall/code/aivm/aivm')


def seg(src: str, node: ast.AST) -> str:
    try:
        text = ast.get_source_segment(src, node) or ''
    except Exception:
        text = ''
    return ' '.join(text.split())


def kw(call: ast.Call, name: str, src: str):
    for k in call.keywords:
        if k.arg == name:
            if isinstance(k.value, ast.Constant):
                return k.value.value
            return seg(src, k.value)
    return None


rows = []
for path in sorted(ROOT.rglob('*.py')):
    src = path.read_text(encoding='utf-8')
    try:
        tree = ast.parse(src)
    except SyntaxError:
        continue

    # map line -> enclosing intent/step role, for calls that inherit it
    scopes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                ctx = item.context_expr
                if (
                    isinstance(ctx, ast.Call)
                    and isinstance(ctx.func, ast.Attribute)
                    and ctx.func.attr in {'intent', 'step'}
                ):
                    scopes.append(
                        (
                            node.lineno,
                            node.end_lineno or node.lineno,
                            ctx.func.attr,
                            kw(ctx, 'role', src),
                            seg(src, ctx.args[0]) if ctx.args else '',
                        )
                    )

    funcs = [
        (n.lineno, n.end_lineno or n.lineno, n.name)
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {'run', 'submit'}:
            continue
        # only CommandManager-ish receivers
        recv = seg(src, node.func.value)
        if not any(
            tok in recv
            for tok in ('mgr', 'manager', 'CommandManager', 'self.mgr')
        ):
            continue
        if not node.args:
            continue

        line = node.lineno
        enclosing = [s for s in scopes if s[0] <= line <= s[1]]
        enclosing_role = None
        enclosing_title = ''
        grouped = bool(enclosing)
        for _, _, kind, role, title in enclosing:
            if role:
                enclosing_role = role
                enclosing_title = title

        fn = ''
        best = -1
        for a, b, name in funcs:
            if a <= line <= b and a > best:
                best, fn = a, name

        rows.append(
            {
                'file': str(path.relative_to(ROOT.parent)),
                'line': line,
                'func': fn,
                'cmd': seg(src, node.args[0])[:90],
                'role': kw(node, 'role', src),
                'sudo': kw(node, 'sudo', src),
                'check': kw(node, 'check', src),
                'summary': (kw(node, 'summary', src) or '')[:70],
                'grouped': grouped,
                'enclosing_role': enclosing_role,
                'enclosing_title': enclosing_title[:40],
            }
        )

json.dump(rows, sys.stdout, indent=1)
