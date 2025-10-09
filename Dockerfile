# Use a lightweight Python base image
FROM python:3.11-slim

# Set environment variables for safety and speed
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8

# Set working directory
WORKDIR /app

# Copy dependency file first (for Docker layer caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app ./app

# Create a non-root user for security
RUN useradd -m sandboxuser
USER sandboxuser

# Expose the default development port
EXPOSE 8000

# ✅ Start FastAPI using Render’s dynamic $PORT
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
