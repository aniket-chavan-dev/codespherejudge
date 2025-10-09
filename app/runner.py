import ast
import io
import sys
import traceback
import multiprocessing
import resource
import re
import time
import importlib
from typing import Tuple, List, Any

# ----- Configuration -----
MEMORY_BYTES = 256 * 1024 * 1024  # 256 MB per process
TIMEOUT_SECONDS = 5
MAX_WORKERS = 8  # Limit concurrency for batch execution

# ----- Allowed / Disallowed modules and names -----
ALLOWED_IMPORTS = {"math", "itertools", "functools", "collections", "heapq", "bisect", "operator", "statistics"}
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
    issues: List[str] = []

    # quick regex-based blacklist checks
    for pattern in BLACKLIST_PATTERNS:
        if re.search(pattern, code, flags=re.IGNORECASE):
            issues.append(f"Disallowed pattern detected: {pattern}")

    # AST checks for more precise decisions
    try:
        tree = ast.parse(code, mode="exec")
    except Exception as e:
        issues.append(f"Syntax error while parsing code: {e}")
        return False, issues

    for node in ast.walk(tree):
        # Import statements: handle Import and ImportFrom separately
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                if base not in ALLOWED_IMPORTS:
                    issues.append(f"Import of '{base}' is not allowed.")
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                issues.append("Relative imports are not allowed.")
            else:
                base = node.module.split(".")[0]
                if base not in ALLOWED_IMPORTS:
                    issues.append(f"Import from '{node.module}' is not allowed.")

        # Disallowed names (e.g., 'os', 'sys', etc.)
        if isinstance(node, ast.Name) and node.id in BLACKLIST_NAMES:
            issues.append(f"Use of '{node.id}' is not allowed.")

        # Attribute access on blacklisted names
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in BLACKLIST_NAMES:
                issues.append(f"Attribute access on '{node.value.id}' is not allowed.")

        # Disallowed calls (open, eval, exec, __import__, etc.)
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

# ---------- Safe builtins and safe __import__ ----------
def _make_safe_builtins():
    base_builtins = __builtins__
    builtin_obj = base_builtins if isinstance(base_builtins, dict) else base_builtins.__dict__

    safe = {name: builtin_obj[name] for name in SAFE_BUILTINS if name in builtin_obj}

    # Allow class creation and module context
    safe["__build_class__"] = builtin_obj["__build_class__"]
    safe["__name__"] = "__main__"

    # Provide a safe __import__ that only allows ALLOWED_IMPORTS
    def _safe_import(name: str, globals=None, locals=None, fromlist=(), level=0):
        base = name.split(".")[0]
        if base not in ALLOWED_IMPORTS:
            raise ImportError(f"Import of '{base}' is not allowed in sandbox.")
        # use importlib to import the module
        return importlib.import_module(name)

    safe["__import__"] = _safe_import

    return safe

# ---------- Run single user code ----------
def _run_user_code(code: str, output_queue: multiprocessing.Queue):
    try:
        # enforce memory limit for this process
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))

        # redirect stdout/stderr
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        start_time = time.perf_counter()
        safe_builtins = _make_safe_builtins()

        # prepare the namespace (globals and locals shared)
        exec_globals: dict = {"__builtins__": safe_builtins}

        # preload allowed modules into exec_globals (optional convenience)
        for mod in ALLOWED_IMPORTS:
            try:
                exec_globals[mod] = importlib.import_module(mod)
            except Exception:
                # if importlib fails here (very unlikely for stdlib), skip it;
                # user import will still use our safe __import__
                pass

        # execute user code in the same dict for globals and locals so helpers/classes are visible
        exec(code, exec_globals, exec_globals)

        exec_time = time.perf_counter() - start_time
        usage = resource.getrusage(resource.RUSAGE_SELF)
        mem_used = usage.ru_maxrss / 1024  # convert KB -> MB (Linux ru_maxrss is KB)

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

# ---------- Batch runner for many problems ----------
def run_multiple_problems(codes: List[str], timeout: int = TIMEOUT_SECONDS):
    def worker(code):
        return run_code_in_sandbox(code, timeout)

    with multiprocessing.Pool(processes=MAX_WORKERS) as pool:
        results = pool.map(worker, codes)

    return results

# ---------- Example usage ----------
if __name__ == "__main__":
    # Example demonstrating 'from collections import deque' now allowed
    sample_code = """
from collections import deque
import math

class TreeNode:
    def __init__(self, val=0, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right

def array_to_tree(arr):
    if not arr:
        return None
    root = TreeNode(arr[0])
    q = deque([root])
    i = 1
    while q and i < len(arr):
        node = q.popleft()
        if i < len(arr) and arr[i] is not None:
            node.left = TreeNode(arr[i]); q.append(node.left)
        i += 1
        if i < len(arr) and arr[i] is not None:
            node.right = TreeNode(arr[i]); q.append(node.right)
        i += 1
    return root

def tree_to_array(root):
    if not root: return []
    res = []; q = deque([root])
    while q:
        node = q.popleft()
        if node:
            res.append(node.val); q.append(node.left); q.append(node.right)
        else:
            res.append(None)
    while res and res[-1] is None: res.pop()
    return res

class Solution:
    def binary_tree_inorder_traversal(self, root):
        # simple inorder traversal returning list
        def inorder(node):
            if not node: return []
            return inorder(node.left) + [node.val] + inorder(node.right)
        return inorder(root)

sol = Solution()
tests = [{'input': {'root': [1, None, 2, 3]}}, {'input': {'root': [1]}}, {'input': {'root': []}}]
for t in tests:
    t['input'] = {k: array_to_tree(v) if isinstance(v, list) else v for k, v in t['input'].items()}
    out = sol.binary_tree_inorder_traversal(**t['input'])
    print(tree_to_array(out) if isinstance(out, tuple) is False else out)
"""

    out, err, t, mem = run_code_in_sandbox(sample_code)
    print("Output:", out)
    print("Error:", err)
    print("Time:", t)
    print("Mem (MB):", mem)
