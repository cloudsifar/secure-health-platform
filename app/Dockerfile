FROM public.ecr.aws/docker/library/python:3.12-slim

LABEL build_timestamp="2026-02-15T21:50:00Z"


# Basic hardening-ish defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Non-root user
RUN useradd -m appuser
USER appuser

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
