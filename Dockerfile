# AutoDefender web console
# Floating 3.12 tag: picks up security patches without jumping to a new Python version
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 autodefender \
    && mkdir -p /data /var/log/suricata \
    && chown autodefender:autodefender /data /var/log/suricata

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=autodefender:autodefender . .

USER autodefender

# Writable state lives in /data (mounted as a volume)
ENV AUTODEFENDER_DB_PATH=/data/autodefender.db \
    AUTODEFENDER_AUDIT_DB=/data/audit.db \
    SURICATA_RULES_DIR=/data/suricata_rules \
    AUTODEFENDER_ALLOWED_DIRS=/data

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)"

# Inside the container Streamlit must listen on all interfaces; docker-compose.yml
# publishes the port on 127.0.0.1 only, so it is still not reachable from other machines.
CMD ["streamlit", "run", "streamlit_app.py", "--server.address=0.0.0.0", "--server.headless=true"]
