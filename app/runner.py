import ast
import io
import sys
import traceback
import multiprocessing
import resource
import re
import time
from typing import Tuple, List, Dict, Optional, Any

# --- Safe & Useful Modules for Algorithmic Problems ---
import math
import itertools
import functools
import collections
import heapq

# ----- Configuration -----
MEMORY_BYTES = 256 * 1024 * 1024  # 256 MB per process
TIMEOUT_SECONDS = 5
MAX_WORKERS = 8  # Limit concurrency for batch execution

# Allowed modules (users can safely import these)
ALLOWED_IMPORTS = {"math", "itertools", "functools", "collections", "heapq"}

# Blacklists
BLACKLIST_NAMES = {
    "os", "sys", "subprocess", "socket", "shutil", "ctypes",
    "multiprocessing", "threading", "pty", "signal", "resource",
    "winreg", "fcntl", "mmap"
}

BLACKLIST_CALLS = {"open", "eval", "exec", "compile", "__import__", "execfile"}

BLACKLIST_PATTERNS = [
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

# ---------- Static code checks ----------
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
        # --- Import Checks ---
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                mod_name = alias.name.split(".")[0]
                if mod_name not in ALLOWED_IMPORTS:
                    issues.append(f"Import of '{mod_name}' is not allowed.")

        # --- Variable or Attribute Checks ---
        if isinstance(node, ast.Name) and node.id in BLACKLIST_NAMES:
            issues.append(f"Use of '{node.id}' is not allowed.")

        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in BLACKLIST_NAMES:
                issues.append(f"Attribute access on '{node.value.id}' is not allowed.")

        # --- Function Call Checks ---
        if isinstance(node, ast.Call):
            func = node.func
            func_name = None
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id in BLACKLIST_NAMES:
                    issues.append(f"Attribute call on '{func.value.id}' is not allowed.")
                func_name = func.attr
            if func_name and func_name in BLACKLIST_CALLS:
                issues.append(f"Call to '{func_name}' is not allowed.")

    return len(issues) == 0, issues

# ---------- Safe builtins ----------
def _make_safe_builtins():
    base_builtins = __builtins__
    builtin_obj = base_builtins if isinstance(base_builtins, dict) else base_builtins.__dict__

    safe = {name: builtin_obj[name] for name in SAFE_BUILTINS if name in builtin_obj}

    # Allow class creation and __main__ context
    safe["__build_class__"] = builtin_obj["__build_class__"]
    safe["__name__"] = "__main__"

    return safe

# ---------- Run single user code ----------
def _run_user_code(code: str, output_queue: multiprocessing.Queue):
    try:
        # Memory limit
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))

        # Capture stdout/stderr
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        # Timer
        start_time = time.perf_counter()

        # Restricted globals
        safe_builtins = _make_safe_builtins()

        # Pre-import whitelisted safe modules
        safe_globals = {"__builtins__": safe_builtins}
        for mod in ALLOWED_IMPORTS:
            safe_globals[mod] = __import__(mod)

        # Execute user code
        exec(code, safe_globals, {})

        # Execution info
        exec_time = time.perf_counter() - start_time
        usage = resource.getrusage(resource.RUSAGE_SELF)
        mem_used = usage.ru_maxrss / 1024

        out = sys.stdout.getvalue()
        err = sys.stderr.getvalue()

        output_queue.put((out.splitlines(), err.strip(), exec_time, mem_used))

    except MemoryError:
        output_queue.put(([], "Error: Memory limit exceeded", 0.0, 0.0))
    except Exception:
        output_queue.put(([], traceback.format_exc(), 0.0, 0.0))
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

# ---------- Run single sandbox ----------
def run_code_in_sandbox(code: str, timeout: int = TIMEOUT_SECONDS):
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

    return q.get()

# ---------- Batch runner for 3000 problems ----------
def run_multiple_problems(codes: List[str], timeout: int = TIMEOUT_SECONDS):
    """
    Run a list of problem codes safely using a multiprocessing pool.
    Returns: [(output_lines, error_text, exec_time, mem_used), ...]
    """
    def worker(code):
        return run_code_in_sandbox(code, timeout)

    with multiprocessing.Pool(processes=MAX_WORKERS) as pool:
        results = pool.map(worker, codes)

    return results


# ---------- Example Usage ----------
if __name__ == "__main__":
    sample_code = """
import math
from collections import deque

class Solution:
    def two_sum(self, nums, target):
        for i in range(len(nums)):
            for j in range(i + 1, len(nums)):
                if nums[i] + nums[j] == target:
                    return [i, j]

sol_obj = Solution()
test_cases = [
    {'input': {'nums': [2, 7, 11, 15], 'target': 9}, 'expected_output': [0, 1]},
    {'input': {'nums': [3, 2, 4], 'target': 6}, 'expected_output': [1, 2]},
    {'input': {'nums': [3, 3], 'target': 6}, 'expected_output': [0, 1]}
]

for data in test_cases:
    ans = sol_obj.two_sum(**data['input'])
    print(ans)
"""

    output_lines, error_text, exec_time, mem_used = run_code_in_sandbox(sample_code)
    print("Output:", output_lines)
    print("Error:", error_text)
    print("Execution Time:", exec_time)
    print("Memory Used (MB):", mem_used)
