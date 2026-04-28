FROM esiqnewacr.azurecr.io/python:3.12-slim

WORKDIR /agent

COPY AIAgent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium + OS dependencies for PDF generation
# Use a shared path so the non-root appuser can find the browser binaries
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install --with-deps chromium \
    && chmod -R o+rx /ms-playwright

# ARG busts Docker cache for all subsequent COPY layers
ARG CACHEBUST=1
COPY AIAgent/app/ app/
COPY AIAgent/main.py .

# Web dashboard served at /
COPY webapp/ webapp/

# Run as non-root user
RUN adduser --disabled-password --no-create-home appuser \
    && chown -R appuser:appuser /agent
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8088/health')" || exit 1

EXPOSE 8088

CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8088"]
