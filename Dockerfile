# Lightweight single-stage Python container for NTRO Log Pre-processing Framework
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code (includes api/static/ landing page)
COPY . .

# Create persistent data directory
RUN mkdir -p /app/data

# Ports: 8000 for FastAPI REST API + Command Portal, 8501 for Streamlit Dashboard
EXPOSE 8000 8501

# Default command launches FastAPI backend (serves Command Portal at localhost:8000)
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
