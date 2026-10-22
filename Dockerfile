FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=UTC

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as a non-root user; it needs write access to data/ for the feed JSON
RUN useradd --create-home appuser && mkdir -p /app/data && chown -R appuser /app
USER appuser

EXPOSE 5052

# app.py starts the APScheduler job (initial fetch + hourly refresh) on import
CMD ["python", "app.py"]
