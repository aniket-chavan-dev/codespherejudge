import ast
import io
import sys
import traceback
import multiprocessing
import resource
import re
import time
from typing import Tuple, List

# ----- Configuration -----
MEMORY_BYTES = 256 * 1024 * 1024   # 256 MB
TIMEOUT_SECONDS = 5

BLACKLIST_NAMES = {
    "os", "sys", "subprocess", "socket", "shutil", "ctypes",
    "multiprocessing", "threading", "pty", "signal", "resource",
    "winreg", "fcntl", "mmap"
}

BLACKLIST_CALLS = {"open", "eval", "exec", "compile", "__import__", "execfile"}

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
    issues = []

    for pattern in BLACKLIST_PATTERNS:
        if re.search(pattern, code, flags=re.IGNORECASE):
            issues.append(f"Disallowed pattern detected: {pattern}")

    try:
        tree = ast.parse(code, mode="exec")
    except Exception as e:
        issues.append(f"Syntax error while parsing code: {e}")
        return False, issues

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            issues.append("Import statements are not allowed.")
        if isinstance(node, ast.Name) and node.id in BLACKLIST_NAMES:
            issues.append(f"Use of '{node.id}' is not allowed.")
        if isinstance(node, ast.Call):
            func = node.func
            func_name = None
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    if func.value.id in BLACKLIST_NAMES:
                        issues.append(f"Attribute call on '{func.value.id}' is not allowed.")
                func_name = func.attr
            if func_name and func_name in BLACKLIST_CALLS:
                issues.append(f"Call to '{func_name}' is not allowed.")
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in BLACKLIST_NAMES:
                issues.append(f"Attribute access on '{node.value.id}' is not allowed.")

    return len(issues) == 0, issues


def _make_safe_builtins():
    base_builtins = __builtins__
    builtin_obj = base_builtins if isinstance(base_builtins, dict) else base_builtins.__dict__

    safe = {name: builtin_obj[name] for name in SAFE_BUILTINS if name in builtin_obj}
    return safe


def _run_user_code(code: str, output_queue: multiprocessing.Queue):
    try:
        # Apply memory limit
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))

        # Redirect stdout/stderr
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        # Start timer
        start_time = time.perf_counter()

        # Prepare restricted globals
        safe_builtins = _make_safe_builtins()
        exec_globals = {"__builtins__": safe_builtins}

        # Execute user code
        exec(code, exec_globals, {})

        # End timer
        exec_time = time.perf_counter() - start_time

        # Get memory usage (in MB)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        mem_used = usage.ru_maxrss / 1024  # Convert KB → MB (Linux gives KB)

        out = sys.stdout.getvalue()
        err = sys.stderr.getvalue()

        output_queue.put((out.splitlines(), err.strip(), exec_time, mem_used))

    except MemoryError:
        output_queue.put(([], "Error: Memory limit exceeded", 0.0, 0.0))
    except Exception:
        output_queue.put(([], traceback.format_exc(), 0.0, 0.0))
    finally:
        try:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
        except Exception:
            pass


def run_code_in_sandbox(code: str, timeout: int = TIMEOUT_SECONDS):
    """
    Runs user code safely and returns:
    (output_lines, error_text, exec_time_seconds, memory_used_MB)
    """
    if not code or not code.strip():
        return [], "Error: Empty code", 0.0, 0.0

    ok, issues = _code_static_checks(code)
    if not ok:
        return [], "Static check failed: " + "; ".join(issues), 0.0, 0.0

    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_run_user_code, args=(code, q))
    p.start()
    p.join(timeout)

    if p.is_alive():
        p.terminate()
        return [], "Error: Execution timed out", timeout, 0.0

    if q.empty():
        return [], "Error: No output captured (possible crash or blocked operation)", 0.0, 0.0

    output_lines, err, exec_time, mem_used = q.get()
    return output_lines, err, exec_time, mem_used
