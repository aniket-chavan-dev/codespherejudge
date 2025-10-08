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

# Expose port
EXPOSE 8000

# Start FastAPI using Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
