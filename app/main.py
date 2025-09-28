from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from .runner import run_code_in_sandbox

app = FastAPI(title="Python Sandbox API")

class CodeRequest(BaseModel):
    code: str  # Single block of Python code

class CodeResponse(BaseModel):
    output: List[str]  # Each line of stdout
    error: str         # stderr if any

@app.post("/run", response_model=CodeResponse)
def run_code(request: CodeRequest):
    output, error = run_code_in_sandbox(request.code)
    return CodeResponse(output=output, error=error)
