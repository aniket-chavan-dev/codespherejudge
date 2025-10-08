from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from .runner import run_code_in_sandbox

app = FastAPI(title="Python Sandbox API")

# ----- Request & Response Models -----
class CodeRequest(BaseModel):
    code: str  # Python code to execute


class CodeResponse(BaseModel):
    output: List[str]     # stdout lines
    error: str            # stderr or sandbox error
    execution_time: float # seconds
    memory_used: float    # MB
# -------------------------------------


@app.post("/run", response_model=CodeResponse)
def run_code(request: CodeRequest):
    output, error, exec_time, mem_used = run_code_in_sandbox(request.code)
    return CodeResponse(
        output=output,
        error=error,
        execution_time=round(exec_time, 4),
        memory_used=round(mem_used, 2)
    )
