"""Terminal formatting helpers: sections, progress bars, status marks.

Unicode box/bar characters are used only on a UTF-8 terminal; everything has
an ASCII form. All text stays English (Persian does not render reliably in
server terminals).
"""
from __future__ import annotations

import sys

WIDTH = 64


def fancy_terminal(stream=None):
    stream = stream or sys.stdout
    return (getattr(stream, "encoding", "") or "").lower().replace("-", "") in ("utf8", "utf8mb4")


class Style:
    def __init__(self, fancy=False, color=False):
        self.fancy, self.color = fancy, color

    def paint(self, text, code):
        return "\033[%sm%s\033[0m" % (code, text) if self.color else text

    def rule(self, heavy=False):
        return ("═" if heavy else "─") * WIDTH if self.fancy else ("=" if heavy else "-") * WIDTH

    def banner(self, title, right=""):
        gap = max(1, WIDTH - 2 - len(title) - len(right))
        return [self.rule(True), "  " + self.paint(title, "1") + " " * gap + right, self.rule(True)]

    def section(self, title):
        return "  " + self.paint(title, "1;36")

    def field(self, label, value, indent=4, width=14):
        return " " * indent + ("%-" + str(width) + "s") % label + str(value)

    def bar(self, pct, width=20):
        pct = max(0, min(100, int(pct)))
        full = int(round(width * pct / 100.0))
        if self.fancy:
            return "█" * full + "░" * (width - full)
        return "#" * full + "." * (width - full)

    def ok(self, text="OK"):
        mark = "✔" if self.fancy else ("" if text else "+")
        return self.paint((mark + " " + text).strip() if text else mark, "32")

    def bad(self, text="FAIL"):
        mark = "✖" if self.fancy else ("" if text else "x")
        return self.paint((mark + " " + text).strip() if text else mark, "31")

    def warn(self, text):
        return self.paint("! " + text, "33")

    def dot(self, good):
        return self.paint("●" if self.fancy else ("+" if good else "-"), "32" if good else "31")

    def dim(self, text):
        return self.paint(text, "2")


def wrap(items, indent, width=WIDTH, separator=", "):
    """Wrap a list of short names onto aligned lines."""
    lines, current = [], ""
    for item in items:
        piece = item if not current else separator + item
        if current and len(" " * indent + current + piece) > width + 6:
            lines.append(current + separator.rstrip())
            current = item
        else:
            current += piece
    if current:
        lines.append(current)
    return [(" " * indent if i else "") + line for i, line in enumerate(lines)]
