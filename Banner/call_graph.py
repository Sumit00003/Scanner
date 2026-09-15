"""
call_graph.py
Build a lightweight static call graph from JS files using regex +
brace-matching. Not a real AST parser -- good enough to answer
"who calls eval / fetch / WebSocket / innerHTML".

If js_parser.py produces an AST, feed its function nodes in via
add_function() and this module will use them.
"""
import re
from libfinder import download_all

# function definitions: function name(...)  |  const name = (...) =>  |  name(a,b) {  |  name: function(
FUNC_DEF_PATTERNS = [
    re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", re.M),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*\(|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)", re.M),
    re.compile(r"\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?function\s*\(", re.M),
    re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{", re.M),
]

CALL_PATTERN = re.compile(r"\b([A-Za-z_$][\w$.]*)\s*\(")

# Sinks we care about for security review
INTERESTING_SINKS = {
    "eval", "Function", "setTimeout", "setInterval",
    "fetch", "XMLHttpRequest", "WebSocket", "EventSource",
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "postMessage", "localStorage.setItem", "sessionStorage.setItem",
    "document.cookie", "location.href", "location.assign",
    "atob", "btoa", "crypto.subtle", "crypto.getRandomValues",
    "require", "import", "execScript", "exec",
}

# not worth recording as calls
IGNORE_CALLS = {
    "if", "for", "while", "switch", "catch", "return", "typeof",
    "new", "delete", "void", "in", "of", "do", "else", "function",
    "class", "super", "this", "yield", "await", "async",
}


def _strip_strings_and_comments(text):
    """
    Very cheap stripper: removes // line comments, /* */ block comments,
    and string/template literals. Keeps indices roughly aligned by
    replacing removed chars with spaces so we don't break positions.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        # line comment
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            if j == -1:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        # block comment
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                j = n
            else:
                j += 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        # string literals
        if c in ("'", '"', "`"):
            quote = c
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def _brace_block(text, start):
    """
    Given index of '{' return (start, end) of matching block, or None.
    """
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return (start, i)
        i += 1
    return None


class CallGraph:
    def __init__(self):
        # func_name -> {"file": url, "start": int, "end": int, "calls": set()}
        self.functions = {}
        # callee -> set of caller function names (or "<top>" for file scope)
        self.callers = {}
        # edge list
        self.edges = []
        # sink hits: sink_name -> list of {file, caller, snippet}
        self.sinks = {}

    # --------------------------------------------------------
    def add_file(self, url, text):
        if not text:
            return
        clean = _strip_strings_and_comments(text)
        self._register_functions(url, text, clean)
        self._register_calls(url, clean)

    # --------------------------------------------------------
    def _register_functions(self, url, raw, clean):
        for pat in FUNC_DEF_PATTERNS:
            for m in pat.finditer(clean):
                name = m.group(1)
                # find the opening brace after the match
                brace = clean.find("{", m.end())
                if brace == -1:
                    continue
                block = _brace_block(clean, brace)
                if not block:
                    continue
                start, end = block
                key = f"{name}@{url}"
                if key in self.functions:
                    continue
                self.functions[key] = {
                    "name": name,
                    "file": url,
                    "start": start,
                    "end": end,
                    "calls": set(),
                    "snippet": raw[m.start(): m.start() + 120].replace("\n", " ").strip(),
                }

    # --------------------------------------------------------
    def _owner_of(self, url, pos):
        """Return the innermost function key containing pos in file url."""
        best = None
        best_span = None
        for key, fn in self.functions.items():
            if fn["file"] != url:
                continue
            if fn["start"] <= pos <= fn["end"]:
                span = fn["end"] - fn["start"]
                if best_span is None or span < best_span:
                    best, best_span = key, span
        return best

    # --------------------------------------------------------
    def _register_calls(self, url, clean):
        for m in CALL_PATTERN.finditer(clean):
            callee = m.group(1)
            base = callee.split(".")[0]
            if base in IGNORE_CALLS:
                continue

            caller_key = self._owner_of(url, m.start())
            caller_name = self.functions[caller_key]["name"] if caller_key else "<top>"

            if caller_key:
                self.functions[caller_key]["calls"].add(callee)

            self.callers.setdefault(callee, set()).add(caller_name)
            self.edges.append({
                "caller": caller_name,
                "callee": callee,
                "file": url,
                "pos": m.start(),
            })

            # sink tracking
            sink = callee
            if sink in INTERESTING_SINKS or base in INTERESTING_SINKS:
                snippet = clean[max(0, m.start() - 40): m.start() + 80].replace("\n", " ")
                self.sinks.setdefault(callee, []).append({
                    "file": url,
                    "caller": caller_name,
                    "pos": m.start(),
                    "snippet": snippet.strip(),
                })

    # --------------------------------------------------------
    def add_function(self, name, file, start, end, calls=None):
        """Public hook so js_parser.py can inject real AST functions."""
        key = f"{name}@{file}"
        self.functions[key] = {
            "name": name, "file": file,
            "start": start, "end": end,
            "calls": set(calls or []), "snippet": "",
        }

    # --------------------------------------------------------
    def sinks_report(self):
        """Summarize sink usage, sorted by hit count."""
        out = []
        for sink, hits in sorted(self.sinks.items(), key=lambda kv: -len(kv[1])):
            out.append({
                "sink": sink,
                "hits": len(hits),
                "files": sorted({h["file"] for h in hits}),
                "callers": sorted({h["caller"] for h in hits}),
                "samples": hits[:5],
            })
        return out

    # --------------------------------------------------------
    def reachable_from(self, entry_point):
        """
        BFS over edges starting at a function name.
        Returns set of function names reachable.
        """
        seen = set()
        queue = [entry_point]
        while queue:
            cur = queue.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for e in self.edges:
                if e["caller"] == cur and e["callee"] not in seen:
                    queue.append(e["callee"])
        return seen

    # --------------------------------------------------------
    def stats(self):
        return {
            "functions": len(self.functions),
            "edges": len(self.edges),
            "unique_callees": len(self.callers),
            "sinks": len(self.sinks),
        }


def build_call_graph(downloads):
    cg = CallGraph()
    for d in downloads:
        if d.get("status") != 200 or not d.get("text"):
            continue
        cg.add_file(d["url"], d["text"])
    return cg
