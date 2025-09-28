import ast
import io
import sys
import traceback
import multiprocessing
import resource
import re
from typing import Tuple, List

# ----- Configuration -----
MEMORY_BYTES = 256 * 1024 * 1024   # 256 MB
TIMEOUT_SECONDS = 5

# Names that should not appear as identifiers (best-effort)
BLACKLIST_NAMES = {
    "os", "sys", "subprocess", "socket", "shutil", "ctypes",
    "multiprocessing", "threading", "pty", "signal", "resource",
    "winreg", "fcntl", "mmap"
}

# Dangerous calls to block (callable names)
BLACKLIST_CALLS = {"open", "eval", "exec", "compile", "__import__", "execfile"}

# Additional suspicious substrings (regex)
BLACKLIST_PATTERNS = [
    r"\bimport\b",
    r"\bfrom\b",
    r"__import__",
    r"\bos\b",
    r"\bsys\b",
    r"\bsubprocess\b",
    r"\bsocket\b",
    r"\bshutil\b",
    r"\bctypes\b",
    r"open\s*\(",
    r"eval\s*\(",
    r"exec\s*\(",
]

# Whitelisted builtins (only safe subset)
SAFE_BUILTINS = {
    "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
    "callable", "chr", "complex", "dict", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "hash", "hex", "int", "isinstance",
    "issubclass", "iter", "len", "list", "map", "max", "min", "next",
    "oct", "ord", "pow", "range", "repr", "reversed", "round", "set",
    "slice", "sorted", "str", "sum", "tuple", "zip", "print"
}
# -------------------------

def _code_static_checks(code: str) -> Tuple[bool, List[str]]:
    """
    Inspect the code using AST and regex to detect disallowed constructs.
    Returns (is_ok, list_of_issues)
    """
    issues = []

    # 1) Quick regex checks
    for pattern in BLACKLIST_PATTERNS:
        if re.search(pattern, code, flags=re.IGNORECASE):
            issues.append(f"Disallowed pattern detected: {pattern}")
    # 2) AST checks
    try:
        tree = ast.parse(code, mode="exec")
    except Exception as e:
        issues.append(f"Syntax error while parsing code: {e}")
        return False, issues

    for node in ast.walk(tree):
        # Imports
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            issues.append("Import statements are not allowed.")
        # Name usage
        if isinstance(node, ast.Name):
            if node.id in BLACKLIST_NAMES:
                issues.append(f"Use of '{node.id}' is not allowed.")
        # Calls to dangerous functions
        if isinstance(node, ast.Call):
            # function can be Name or Attribute
            func = node.func
            func_name = None
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                # attribute access like os.system
                if isinstance(func.value, ast.Name):
                    name0 = func.value.id
                    if name0 in BLACKLIST_NAMES:
                        issues.append(f"Attribute call on '{name0}' is not allowed.")
                func_name = func.attr
            if func_name and func_name in BLACKLIST_CALLS:
                issues.append(f"Call to '{func_name}' is not allowed.")
        # Attribute usage (e.g., os.system)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in BLACKLIST_NAMES:
                issues.append(f"Attribute access on '{node.value.id}' is not allowed.")

    is_ok = len(issues) == 0
    return is_ok, issues


def _make_safe_builtins():
    """
    Build a restricted __builtins__ dict exposing only SAFE_BUILTINS.
    """
    base_builtins = __builtins__
    if isinstance(base_builtins, dict):
        builtin_obj = base_builtins
    else:
        builtin_obj = base_builtins.__dict__

    safe = {}
    for name in SAFE_BUILTINS:
        if name in builtin_obj:
            safe[name] = builtin_obj[name]
    # Note: do NOT include __import__, open, eval, exec, etc.
    return safe


def _run_user_code(code: str, output_queue: multiprocessing.Queue):
    """
    Worker process to execute user code with resource limits and restricted builtins.
    Returns (output_lines, stderr_text) via queue.
    """
    try:
        # Apply memory limit (address space)
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))

        # Redirect stdout/stderr
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        # Prepare restricted globals
        safe_builtins = _make_safe_builtins()
        exec_globals = {"__builtins__": safe_builtins}

        # Execute
        exec(code, exec_globals, {})

        out = sys.stdout.getvalue()
        err = sys.stderr.getvalue()

        output_lines = out.splitlines() if out else []
        output_queue.put((output_lines, err.strip()))

    except MemoryError:
        output_queue.put(([], "Error: Memory limit exceeded"))
    except Exception:
        output_queue.put(([], traceback.format_exc()))
    finally:
        # restore
        try:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
        except Exception:
            pass


def run_code_in_sandbox(code: str, timeout: int = TIMEOUT_SECONDS) -> Tuple[List[str], str]:
    """
    Public function to run user code safely.
    Returns (output_lines, error_text).
    """

    # 0) Quick empty-check
    if not code or not code.strip():
        return [], "Error: Empty code"

    # 1) Static checks
    ok, issues = _code_static_checks(code)
    if not ok:
        return [], "Static check failed: " + "; ".join(issues)

    # 2) Run in worker process with timeout
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_run_user_code, args=(code, q))
    p.start()
    p.join(timeout)

    if p.is_alive():
        p.terminate()
        return [], "Error: Execution timed out"

    if q.empty():
        return [], "Error: No output captured (possible crash or blocked operation)"

    output_lines, err = q.get()
    return output_lines, err
