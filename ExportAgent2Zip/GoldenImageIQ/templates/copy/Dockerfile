FROM esiqnewacr.azurecr.io/base-playwright:latest

WORKDIR /app

# Cache bust for rebuilds
ARG CACHEBUST=1

# Install Python dependencies
COPY AIAgent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install chromium --with-deps 2>/dev/null || true

# Copy application code
COPY AIAgent/ .
COPY webapp/ /app/webapp/

# Non-root user
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8088

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8088/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8088"]
