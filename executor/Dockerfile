FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 sf && mkdir -p /data /etc/sf-gateway && chown sf /data /etc/sf-gateway
COPY app ./app
USER sf
EXPOSE 8200
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8200/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8200"]
